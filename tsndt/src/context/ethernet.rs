use std::collections::{HashMap, HashSet};

use aya::maps::MapData;
use color_eyre::eyre::Result;
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::{
    layout::{Constraint, Layout, Rect},
    style::{Color, Modifier, Style, Stylize},
    symbols,
    text::Span,
    widgets::{
        Axis, BarChart, Block, Chart, Dataset, LegendPosition, List, ListDirection, ListItem,
        ListState,
    },
    Frame,
};

use super::TsndtContext;
use crate::app::TICK_RATE_MS;

const DISABLED_COLOR: Color = Color::Rgb(100, 100, 100);
const ZOOM_CONTEXT_COLOR: Color = Color::LightBlue;
const DEFAULT_HISTOGRAM_WIDTH_PERCENTAGE: u16 = 25;
const DEFAULT_BYTE_COUNTERS_HEIGHT_PERCENTAGE: u16 = 50;
const CONTEXT_NAME: &str = "Ethernet";
const IDLE_MAC_ADDR_TIMEOUT_SEC: u64 = 300;
const IDLE_MAC_ADDR_TIMEOUT_NUM_TICKS: f64 =
    IDLE_MAC_ADDR_TIMEOUT_SEC as f64 * (1000.0 / TICK_RATE_MS as f64);

#[derive(Clone, Eq, PartialEq, Hash)]
enum ZoomContext {
    Packet,
    Byte,
}

pub(crate) struct EthernetContext {
    pub(crate) model: EthernetModel,
    pub(crate) view: EthernetView,
}

pub(crate) struct EthernetView {
    src_macs_state: ListState,
    packet_count_y_bounds: [f64; 2],
    byte_count_y_bounds: [f64; 2],
    histogram_width_percentage: u16,
    byte_counter_height_percentage: u16,
    zoom_context: ZoomContext,
    autoscaling: HashMap<ZoomContext, bool>,
}

pub(crate) struct EthernetModel {
    src_macs: Vec<[u8; 6]>,
    last_active_tick: HashMap<[u8; 6], f64>,
    cumul_packet_counts: HashMap<[u8; 6], u32>,
    tick_packet_count_data: HashMap<[u8; 6], Vec<(f64, f64)>>,
    cumul_byte_counts: HashMap<[u8; 6], u64>,
    tick_byte_count_data: HashMap<[u8; 6], Vec<(f64, f64)>>,
    tick_count: f64,
    displaying: HashSet<[u8; 6]>,
    window_size: f64,
    window: [f64; 2],
}

fn get_mac_string(mac: &[u8; 6]) -> String {
    let hex_strings: Vec<String> = mac.iter().map(|octet| format!("{:02x?}", octet)).collect();
    hex_strings.join(":")
}

fn get_autoscale_axis_bound(max_val: f64) -> f64 {
    let mut axis_val = 1.0;
    let mut val = max_val;
    while val >= 10.0 {
        val /= 10.0;
        axis_val *= 10.0;
    }
    axis_val * f64::ceil(val)
}

impl TsndtContext for EthernetContext {
    fn get_context_name(&self) -> String {
        String::from(CONTEXT_NAME)
    }

    fn get_command_help(&self) -> Vec<String> {
        vec![String::from(
            "(↑/↓) Select address, (t) Toggle address monitoring, (s) Sort address values",
        )]
    }

    fn handle_tick(&mut self, bpf: &mut aya::Ebpf) -> Result<()> {
        self.model.on_tick(bpf)
    }

    fn handle_key_event(&mut self, key: KeyEvent, _bpf: &mut aya::Ebpf) -> Result<()> {
        match key.code {
            KeyCode::Char('b') => {
                self.view.zoom_context = ZoomContext::Byte;
            }
            KeyCode::Char('p') => {
                self.view.zoom_context = ZoomContext::Packet;
            }
            KeyCode::Char('a') => {
                let val = !self.view.autoscaling[&self.view.zoom_context];
                self.view
                    .autoscaling
                    .insert(self.view.zoom_context.clone(), val);
            }
            KeyCode::Char('s') => {
                self.model.src_macs.sort();
            }
            KeyCode::Char('-') => match self.view.zoom_context {
                ZoomContext::Packet => self.view.packet_count_y_bounds[1] *= 2.0,
                ZoomContext::Byte => self.view.byte_count_y_bounds[1] *= 2.0,
            },
            KeyCode::Char('+') => match self.view.zoom_context {
                ZoomContext::Packet => self.view.packet_count_y_bounds[1] /= 2.0,
                ZoomContext::Byte => self.view.byte_count_y_bounds[1] /= 2.0,
            },
            KeyCode::Up => {
                if key.modifiers.contains(KeyModifiers::CONTROL) {
                    // Change the height of the plots
                    if self.view.byte_counter_height_percentage < 100 {
                        self.view.byte_counter_height_percentage += 1;
                    }
                } else {
                    // Move the selected item in the interface list up
                    let selected = self.view.src_macs_state.selected().unwrap_or(0);
                    let candidate = if selected > 0 { selected - 1 } else { 0 };
                    self.view.src_macs_state.select(Some(candidate));
                }
            }
            KeyCode::Down => {
                if key.modifiers.contains(KeyModifiers::CONTROL) {
                    // Change the height of the plots
                    if self.view.byte_counter_height_percentage > 0 {
                        self.view.byte_counter_height_percentage -= 1;
                    }
                } else {
                    // Move the selected item in the interface list down
                    let selected = self.view.src_macs_state.selected().unwrap_or(0);
                    let candidate = selected + 1;
                    if candidate < self.model.src_macs.len() {
                        self.view.src_macs_state.select(Some(candidate));
                    }
                }
            }
            KeyCode::Right => {
                if key.modifiers.contains(KeyModifiers::CONTROL)
                    && self.view.histogram_width_percentage > 0
                {
                    self.view.histogram_width_percentage -= 1;
                }
            }
            KeyCode::Left => {
                if key.modifiers.contains(KeyModifiers::CONTROL)
                    && self.view.histogram_width_percentage < 100
                {
                    self.view.histogram_width_percentage += 1;
                }
            }
            KeyCode::Char('t') => {
                let selected = self.view.src_macs_state.selected().unwrap_or(0);
                let src_mac = self.model.src_macs.get(selected).cloned();
                if let Some(src_mac) = src_mac {
                    self.model.toggle_display(&src_mac);
                } else {
                    tracing::warn!(
                        "Could not toggle selected source MAC address: there may be a bug",
                    );
                }
            }
            _ => {}
        }

        Ok(())
    }

    fn draw(&mut self, frame: &mut Frame, context_area: Rect) {
        self.view.draw(frame, &self.model, context_area);
    }
}

impl EthernetContext {
    pub(crate) fn new() -> Self {
        let src_macs_state = ListState::default().with_selected(Some(0));

        // Turn on autoscaling by default
        let autoscaling = HashMap::from([(ZoomContext::Byte, true), (ZoomContext::Packet, true)]);

        Self {
            model: EthernetModel {
                src_macs: Vec::new(),
                window_size: 50.0,
                window: [0.0, 50.0],
                tick_count: 0.0,
                last_active_tick: HashMap::new(),
                tick_packet_count_data: HashMap::new(),
                cumul_packet_counts: HashMap::new(),
                tick_byte_count_data: HashMap::new(),
                cumul_byte_counts: HashMap::new(),
                displaying: HashSet::new(),
            },
            view: EthernetView {
                packet_count_y_bounds: [0.0, 40.0],
                byte_count_y_bounds: [0.0, 50000.0],
                histogram_width_percentage: DEFAULT_HISTOGRAM_WIDTH_PERCENTAGE,
                zoom_context: ZoomContext::Packet,
                byte_counter_height_percentage: DEFAULT_BYTE_COUNTERS_HEIGHT_PERCENTAGE,
                autoscaling,
                src_macs_state,
            },
        }
    }
}

impl EthernetModel {
    fn on_tick(&mut self, bpf: &mut aya::Ebpf) -> Result<()> {
        self.tick_count += 1.0;

        let src_mac_rx_packet_counters: aya::maps::PerCpuHashMap<&MapData, [u8; 6], u32> =
            aya::maps::PerCpuHashMap::try_from(bpf.map("SRC_MAC_RX_PACKET_COUNTERS").unwrap())?;

        let src_mac_rx_byte_counters: aya::maps::PerCpuHashMap<&MapData, [u8; 6], u64> =
            aya::maps::PerCpuHashMap::try_from(bpf.map("SRC_MAC_RX_BYTE_COUNTERS").unwrap())?;

        let num_cpus =
            aya::util::nr_cpus().unwrap_or_else(|_| panic!("Could not get number of CPUs"));

        for src_mac_packet_counter_entry in src_mac_rx_packet_counters.iter() {
            let (src_mac, values) = src_mac_packet_counter_entry?;

            // Add the source MAC to the list if it was not being tracked with an active tick and
            // initialize the counts to 0.
            if !self.last_active_tick.contains_key(&src_mac) {
                self.src_macs.push(src_mac);
                self.cumul_byte_counts.insert(src_mac, 0);
                self.cumul_packet_counts.insert(src_mac, 0);
                self.tick_byte_count_data.insert(src_mac, Vec::new());
                self.tick_packet_count_data.insert(src_mac, Vec::new());
            }

            let l = self.tick_packet_count_data.get_mut(&src_mac).unwrap();
            let prev_val = *self.cumul_packet_counts.get(&src_mac).unwrap();

            if l.len() as f64 > self.window_size {
                l.remove(0);
            }

            let mut across_cpus_val: u32 = 0;
            for cpu_id in 0..num_cpus {
                if let Some(cpu_val) = values.get(cpu_id) {
                    across_cpus_val += cpu_val;
                }
            }

            l.push((self.tick_count, (across_cpus_val - prev_val) as f64));
            self.cumul_packet_counts.insert(src_mac, across_cpus_val);

            // If new data arrived for this MAC entry, then update its last active tick to the current tick
            // FIXME: this does not work. It seems to remove for a single tick and then re-add things.
            if across_cpus_val > prev_val {
                *self
                    .last_active_tick
                    .entry(src_mac)
                    .or_insert(self.tick_count) = self.tick_count;
            }
        }

        for src_mac_byte_counter_entry in src_mac_rx_byte_counters.iter() {
            let (src_mac, values) = src_mac_byte_counter_entry?;

            let l = self.tick_byte_count_data.get_mut(&src_mac).unwrap();
            let prev_val = self.cumul_byte_counts.get(&src_mac).unwrap();

            if l.len() as f64 > self.window_size {
                l.remove(0);
            }

            let mut across_cpus_val: u64 = 0;
            for cpu_id in 0..num_cpus {
                if let Some(cpu_val) = values.get(cpu_id) {
                    across_cpus_val += cpu_val;
                }
            }

            l.push((self.tick_count, (across_cpus_val - prev_val) as f64));
            self.cumul_byte_counts.insert(src_mac, across_cpus_val);
        }

        // Remove MAC addresses which have been inactive for the duration of the timeout period
        let mut to_remove = Vec::new();
        for (src_mac, last_active_tick) in &self.last_active_tick {
            // Check if the timeout has occurred
            if self.tick_count - IDLE_MAC_ADDR_TIMEOUT_NUM_TICKS >= *last_active_tick {
                to_remove.push(*src_mac);
            }
        }

        for src_mac in &to_remove {
            self.cumul_byte_counts.remove(src_mac);
            self.cumul_packet_counts.remove(src_mac);
            self.tick_byte_count_data.remove(src_mac);
            self.tick_packet_count_data.remove(src_mac);
            self.last_active_tick.remove(src_mac);
            if let Some(index) = self.src_macs.iter().position(|value| value == src_mac) {
                self.src_macs.swap_remove(index);
            }

            let mut src_mac_rx_packet_counters: aya::maps::PerCpuHashMap<
                &mut MapData,
                [u8; 6],
                u32,
            > = aya::maps::PerCpuHashMap::try_from(
                bpf.map_mut("SRC_MAC_RX_PACKET_COUNTERS").unwrap(),
            )?;

            src_mac_rx_packet_counters.remove(src_mac)?;

            let mut src_mac_rx_byte_counters: aya::maps::PerCpuHashMap<&mut MapData, [u8; 6], u64> =
                aya::maps::PerCpuHashMap::try_from(
                    bpf.map_mut("SRC_MAC_RX_BYTE_COUNTERS").unwrap(),
                )?;

            src_mac_rx_byte_counters.remove(src_mac)?;
        }

        if self.tick_count > self.window_size {
            self.window[0] += 1.0;
            self.window[1] += 1.0;
        }

        Ok(())
    }

    fn toggle_display(&mut self, src_mac: &[u8; 6]) {
        if self.displaying.contains(src_mac) {
            self.displaying.remove(src_mac);
        } else {
            self.displaying.insert(*src_mac);
        }
    }
}

impl EthernetView {
    fn draw(&mut self, frame: &mut Frame, model: &EthernetModel, context_area: Rect) {
        let [observed_mac_list, plots] =
            Layout::horizontal([Constraint::Percentage(15), Constraint::Fill(1)])
                .areas(context_area);
        let [packet_counts, byte_counts] = Layout::vertical([
            Constraint::Fill(1),
            Constraint::Percentage(self.byte_counter_height_percentage),
        ])
        .areas(plots);
        let [packet_time_series, packet_cumul_histogram] = Layout::horizontal([
            Constraint::Fill(1),
            Constraint::Percentage(self.histogram_width_percentage),
        ])
        .areas(packet_counts);
        let [byte_time_series, byte_cumul_histogram] = Layout::horizontal([
            Constraint::Fill(1),
            Constraint::Percentage(self.histogram_width_percentage),
        ])
        .areas(byte_counts);

        self.render_list(frame, observed_mac_list, model);
        self.render_packet_time_series(frame, packet_time_series, model);
        self.render_packet_cumul_histogram(frame, packet_cumul_histogram, model);
        self.render_byte_time_series(frame, byte_time_series, model);
        self.render_byte_cumul_histogram(frame, byte_cumul_histogram, model);
    }

    fn render_packet_time_series(&mut self, frame: &mut Frame, area: Rect, model: &EthernetModel) {
        let x_labels = vec![
            Span::styled(
                format!("{}", model.window[0]),
                Style::default().add_modifier(Modifier::BOLD),
            ),
            Span::raw(format!("{}", (model.window[0] + model.window[1]) / 2.0)),
            Span::styled(
                format!("{}", model.window[1]),
                Style::default().add_modifier(Modifier::BOLD),
            ),
        ];

        // Initialize max_val to 1.0 to avoid a quirk in the time series plot with autoscaling.
        // If all values are 0 in the plot, and autoscaling starts at 0, then no points get plotted.
        let mut max_val = 1.0f64;
        let mut datasets = Vec::with_capacity(model.src_macs.len());
        let mut color_index = 1u8;
        for src_mac in &model.src_macs {
            if model.displaying.contains(src_mac) {
                let data = model.tick_packet_count_data.get(src_mac).unwrap();
                let src_mac_max_val = data.iter().max_by(|a, b| a.1.total_cmp(&b.1)).unwrap().1;
                max_val = if max_val.total_cmp(&src_mac_max_val).is_ge() {
                    max_val
                } else {
                    src_mac_max_val
                };
                let dataset = Dataset::default()
                    .name(get_mac_string(src_mac))
                    .marker(symbols::Marker::Dot)
                    .style(Style::default().fg(Color::Indexed(color_index)))
                    .data(data);
                datasets.push(dataset);
                color_index += 1;
            }
        }

        if self.autoscaling[&ZoomContext::Packet] {
            let upper_bound = get_autoscale_axis_bound(max_val);
            self.packet_count_y_bounds[1] = upper_bound;
        };

        let y_labels = [
            "0".into(),
            (self.packet_count_y_bounds[1] / 2.0).to_string().bold(),
            self.packet_count_y_bounds[1].to_string().bold(),
        ];

        let border_style = match self.zoom_context {
            ZoomContext::Packet => Style::default().fg(ZOOM_CONTEXT_COLOR),
            ZoomContext::Byte => Style::default(),
        };

        let y_axis_title = if self.autoscaling[&ZoomContext::Packet] {
            "Packets (autoscaled)"
        } else {
            "Packets (manual zoom)"
        };

        let chart = Chart::new(datasets)
            .block(
                Block::bordered()
                    .border_style(border_style)
                    .title(format!("Packet count per {} ms", TICK_RATE_MS)),
            )
            .x_axis(
                Axis::default()
                    .title("Time")
                    .style(Style::default().fg(DISABLED_COLOR))
                    .labels(x_labels)
                    .bounds(model.window),
            )
            .y_axis(
                Axis::default()
                    .title(y_axis_title)
                    .style(Style::default().fg(DISABLED_COLOR))
                    .labels(y_labels)
                    .bounds(self.packet_count_y_bounds),
            )
            .hidden_legend_constraints((Constraint::Min(0), Constraint::Min(0)))
            .legend_position(Some(LegendPosition::TopLeft));

        frame.render_widget(chart, area);
    }

    fn render_packet_cumul_histogram(
        &mut self,
        frame: &mut Frame,
        area: Rect,
        model: &EthernetModel,
    ) {
        let mut target_src_macs: Vec<&[u8; 6]> = Vec::with_capacity(model.src_macs.len());
        for src_mac in &model.src_macs {
            if model.displaying.contains(src_mac) {
                target_src_macs.push(src_mac);
            }
        }

        let mut mac_strs: Vec<String> = Vec::with_capacity(target_src_macs.len());
        for src_mac in &target_src_macs {
            mac_strs.push(get_mac_string(src_mac));
        }

        let mut data: Vec<(&str, u64)> = Vec::with_capacity(target_src_macs.len());
        for (i, src_mac) in target_src_macs.iter().enumerate() {
            let val = model.cumul_packet_counts.get(*src_mac).unwrap();
            data.push((mac_strs.get(i).unwrap(), *val as u64));
        }

        data.sort_by_key(|datum| std::cmp::Reverse(datum.1));

        let bar_chart = BarChart::default()
            .block(Block::bordered().title("Cumulative packet count"))
            .bar_width(10)
            .data(&data);

        frame.render_widget(bar_chart, area);
    }

    fn render_byte_time_series(&mut self, frame: &mut Frame, area: Rect, model: &EthernetModel) {
        let x_labels = vec![
            Span::styled(
                format!("{}", model.window[0]),
                Style::default().add_modifier(Modifier::BOLD),
            ),
            Span::raw(format!("{}", (model.window[0] + model.window[1]) / 2.0)),
            Span::styled(
                format!("{}", model.window[1]),
                Style::default().add_modifier(Modifier::BOLD),
            ),
        ];

        // Initialize max_val to 1.0 to avoid a quirk in the time series plot with autoscaling.
        // If all values are 0 in the plot, and autoscaling starts at 0, then no points get plotted.
        let mut max_val = 1.0f64;
        let mut datasets = Vec::with_capacity(model.src_macs.len());
        let mut color_index = 1;
        for src_mac in &model.src_macs {
            if model.displaying.contains(src_mac) {
                let data = model.tick_byte_count_data.get(src_mac).unwrap();
                let src_mac_max_val = data.iter().max_by(|a, b| a.1.total_cmp(&b.1)).unwrap().1;
                max_val = if max_val.total_cmp(&src_mac_max_val).is_ge() {
                    max_val
                } else {
                    src_mac_max_val
                };
                let dataset = Dataset::default()
                    .name(get_mac_string(src_mac))
                    .marker(symbols::Marker::Dot)
                    .style(Style::default().fg(Color::Indexed(color_index)))
                    .data(data);
                datasets.push(dataset);
                color_index += 1;
            }
        }

        if self.autoscaling[&ZoomContext::Byte] {
            let upper_bound = get_autoscale_axis_bound(max_val);
            self.byte_count_y_bounds[1] = upper_bound;
        };

        let y_labels = [
            "0".into(),
            (self.byte_count_y_bounds[1] / 2.0).to_string().bold(),
            self.byte_count_y_bounds[1].to_string().bold(),
        ];

        let border_style = match self.zoom_context {
            ZoomContext::Packet => Style::default(),
            ZoomContext::Byte => Style::default().fg(ZOOM_CONTEXT_COLOR),
        };

        let y_axis_title = if self.autoscaling[&ZoomContext::Byte] {
            "Bytes (autoscaled)"
        } else {
            "Bytes (manual zoom)"
        };

        let chart = Chart::new(datasets)
            .block(
                Block::bordered()
                    .border_style(border_style)
                    .title(format!("Byte count per {} ms", TICK_RATE_MS)),
            )
            .x_axis(
                Axis::default()
                    .title("Time")
                    .style(Style::default().fg(DISABLED_COLOR))
                    .labels(x_labels)
                    .bounds(model.window),
            )
            .y_axis(
                Axis::default()
                    .title(y_axis_title)
                    .style(Style::default().fg(DISABLED_COLOR))
                    .labels(y_labels)
                    .bounds(self.byte_count_y_bounds),
            );

        frame.render_widget(chart, area);
    }

    fn render_byte_cumul_histogram(
        &mut self,
        frame: &mut Frame,
        area: Rect,
        model: &EthernetModel,
    ) {
        let mut target_src_macs: Vec<&[u8; 6]> = Vec::with_capacity(model.src_macs.len());
        for src_mac in &model.src_macs {
            if model.displaying.contains(src_mac) {
                target_src_macs.push(src_mac);
            }
        }

        let mut mac_strs: Vec<String> = Vec::with_capacity(target_src_macs.len());
        for src_mac in &target_src_macs {
            mac_strs.push(get_mac_string(src_mac));
        }

        let mut data: Vec<(&str, u64)> = Vec::with_capacity(target_src_macs.len());
        for (i, src_mac) in target_src_macs.iter().enumerate() {
            let val = model.cumul_byte_counts.get(*src_mac).unwrap();
            data.push((mac_strs.get(i).unwrap(), *val));
        }

        data.sort_by_key(|datum| std::cmp::Reverse(datum.1));

        let bar_chart = BarChart::default()
            .block(Block::bordered().title("Cumulative byte count"))
            .bar_width(10)
            .data(&data);

        frame.render_widget(bar_chart, area);
    }

    fn render_list(&mut self, frame: &mut Frame, list_area: Rect, model: &EthernetModel) {
        let src_macs: Vec<ListItem> = model
            .src_macs
            .iter()
            .map(|src_mac| {
                let color = if model.displaying.contains(src_mac) {
                    Color::default()
                } else {
                    DISABLED_COLOR
                };
                let li = ListItem::new(get_mac_string(src_mac)).style(Style::default().fg(color));
                li
            })
            .collect();

        // If the list was empty, then the selected index may be set to none.
        // Once the list has entries in it, default to selecting index 0 if
        // it was none.
        if self.src_macs_state.selected().is_none() && !src_macs.is_empty() {
            self.src_macs_state.select(Some(0));
        }

        let list = List::new(src_macs)
            .block(Block::bordered().title("Source MAC Address List"))
            .style(Style::new().white())
            .highlight_style(Style::new().italic())
            .highlight_symbol(">")
            .repeat_highlight_symbol(true)
            .direction(ListDirection::TopToBottom);

        frame.render_stateful_widget(list, list_area, &mut self.src_macs_state);
    }
}
