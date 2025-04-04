use std::collections::HashMap;

use aya::{
    maps::{MapData, PerCpuValues},
    programs::{xdp::XdpLinkId, Xdp, XdpFlags},
};
use aya_log::EbpfLogger;
use color_eyre::eyre::{eyre, Context, Result};
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use network_interface::{NetworkInterface, NetworkInterfaceConfig};
use ratatui::{
    layout::{Constraint, Layout, Rect},
    style::{Color, Modifier, Style, Stylize},
    symbols::{self},
    text::Span,
    widgets::{
        Axis, BarChart, Block, Chart, Dataset, LegendPosition, List, ListDirection, ListItem,
        ListState,
    },
    Frame,
};
use tsndt_common::Counter;

use super::TsndtContext;
use crate::app::TICK_RATE_MS;

const DISABLED_COLOR: Color = Color::Rgb(100, 100, 100);
const ZOOM_CONTEXT_COLOR: Color = Color::LightBlue;
const DEFAULT_HISTOGRAM_WIDTH_PERCENTAGE: u16 = 25;
const DEFAULT_BYTE_COUNTERS_HEIGHT_PERCENTAGE: u16 = 50;
const CONTEXT_NAME: &str = "Network Interfaces";

#[derive(Clone, Eq, PartialEq, Hash)]
enum ZoomContext {
    Packet,
    Byte,
}

pub(crate) struct NetworkInterfaceContext {
    pub(crate) model: NetworkInterfaceModel,
    pub(crate) view: NetworkInterfaceView,
}

pub(crate) struct NetworkInterfaceView {
    interfaces_state: ListState,
    packet_count_y_bounds: [f64; 2],
    byte_count_y_bounds: [f64; 2],
    histogram_width_percentage: u16,
    byte_counter_height_percentage: u16,
    zoom_context: ZoomContext,
    autoscaling: HashMap<ZoomContext, bool>,
}

pub(crate) struct NetworkInterfaceModel {
    interfaces: Vec<NetworkInterface>,
    cumul_packet_counts: HashMap<u32, u32>,
    tick_packet_count_data: HashMap<u32, Vec<(f64, f64)>>,
    cumul_byte_counts: HashMap<u32, u64>,
    tick_byte_count_data: HashMap<u32, Vec<(f64, f64)>>,
    tick_count: f64,
    collecting: HashMap<u32, bool>,
    xdp_link_ids: HashMap<u32, XdpLinkId>,
    window_size: f64,
    window: [f64; 2],
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

fn init_ebpf_programs(
    interfaces: &Vec<NetworkInterface>,
    bpf: &mut aya::Ebpf,
) -> Result<HashMap<u32, XdpLinkId>> {
    EbpfLogger::init(bpf).unwrap();

    let mut xdp_link_ids = HashMap::new();

    let program: &mut Xdp = bpf.program_mut("xdp_tsndt").unwrap().try_into().unwrap();
    program.load().unwrap();

    let num_cpus =
        aya::util::nr_cpus().unwrap_or_else(|_| panic!("Unable to obtain the number of CPUs"));

    for interface in interfaces {
        let link_id = program.attach(&interface.name, XdpFlags::default())
            .context("failed to attach the XDP program with default flags - try changing XdpFlags::default() to XdpFlags::SKB_MODE").unwrap();
        xdp_link_ids.insert(interface.index, link_id);
    }

    let mut ebpf_interface_rx_counters: aya::maps::PerCpuHashMap<&mut MapData, u32, Counter> =
        aya::maps::PerCpuHashMap::try_from(bpf.map_mut("INTERFACE_RX_COUNTERS").unwrap()).unwrap();

    for interface in interfaces {
        if ebpf_interface_rx_counters.get(&interface.index, 0).is_err() {
            ebpf_interface_rx_counters.insert(
                interface.index,
                PerCpuValues::try_from(vec![
                    Counter {
                        bytes: 0,
                        packets: 0
                    };
                    num_cpus
                ])?,
                0,
            )?;
        }
    }

    Ok(xdp_link_ids)
}

impl TsndtContext for NetworkInterfaceContext {
    fn get_context_name(&self) -> String {
        String::from(CONTEXT_NAME)
    }

    fn get_command_help(&self) -> Vec<String> {
        vec![
            String::from("(↑/↓) Select interface, (t) Toggle interface monitoring"),
            String::from(
                "(b/p) Select plot zoom context, (a) Toggle autoscaling, (+/-) Y axis zoom",
            ),
            String::from("(Ctrl + ←/→): Change plot widths, (Ctrl + ↑/↓): Change plot heights"),
        ]
    }

    fn handle_tick(&mut self, bpf: &mut aya::Ebpf) -> Result<()> {
        self.model.on_tick(bpf)
    }

    fn handle_key_event(&mut self, key: KeyEvent, bpf: &mut aya::Ebpf) -> Result<()> {
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
                    let selected = self.view.interfaces_state.selected().unwrap_or(0);
                    let candidate = if selected > 0 { selected - 1 } else { 0 };
                    self.view.interfaces_state.select(Some(candidate));
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
                    let selected = self.view.interfaces_state.selected().unwrap_or(0);
                    let candidate = selected + 1;
                    if candidate < self.model.interfaces.len() {
                        self.view.interfaces_state.select(Some(candidate));
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
                let selected = self.view.interfaces_state.selected().unwrap_or(0);
                let interface = self.model.interfaces.get(selected);
                if let Some(interface) = interface {
                    let interface_index = interface.index;
                    let interface_name = interface.name.clone();
                    let result = self.model.toggle_ebpf_program(interface_index, bpf);
                    if let Err(report) = result {
                        tracing::warn!("Failed to toggle interface {}: {}", interface_name, report);
                    }
                } else {
                    tracing::warn!(
                        "Could not toggle selected interface (list index {}): there may be a bug",
                        selected
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

impl NetworkInterfaceContext {
    pub(crate) fn new(bpf: &mut aya::Ebpf) -> Self {
        // Initialize the interfaces list to include all known interfaces on the host system
        let mut interfaces = NetworkInterface::show().unwrap();
        interfaces.sort_by(|a, b| a.index.partial_cmp(&b.index).unwrap());
        let interfaces_state = ListState::default().with_selected(Some(0));

        // Initialize packet counts to 0
        let mut cur_packet_counts = HashMap::new();
        let mut cumul_packet_counts = HashMap::new();
        let mut tick_packet_count_data: HashMap<u32, Vec<(f64, f64)>> = HashMap::new();
        for interface in &interfaces {
            tick_packet_count_data.insert(interface.index, vec![(0.0, 0.0); 1]);
            cur_packet_counts.insert(interface.index, 0);
            cumul_packet_counts.insert(interface.index, 0);
        }

        // Initialize byte counts to 0
        let mut cur_byte_counts = HashMap::new();
        let mut cumul_byte_counts = HashMap::new();
        let mut tick_byte_count_data: HashMap<u32, Vec<(f64, f64)>> = HashMap::new();
        for interface in &interfaces {
            tick_byte_count_data.insert(interface.index, vec![(0.0, 0.0); 1]);
            cur_byte_counts.insert(interface.index, 0);
            cumul_byte_counts.insert(interface.index, 0);
        }

        // Enable collection on all interfaces
        let mut collecting = HashMap::new();
        for interface in &interfaces {
            collecting.insert(interface.index, true);
        }

        // Load the eBPF programs
        let xdp_link_ids = init_ebpf_programs(&interfaces, bpf).unwrap();

        // Turn on autoscaling by default
        let autoscaling = HashMap::from([(ZoomContext::Byte, true), (ZoomContext::Packet, true)]);

        Self {
            model: NetworkInterfaceModel {
                window_size: 50.0,
                window: [0.0, 50.0],
                tick_count: 0.0,
                interfaces,
                tick_packet_count_data,
                cumul_packet_counts,
                tick_byte_count_data,
                cumul_byte_counts,
                collecting,
                xdp_link_ids,
            },
            view: NetworkInterfaceView {
                packet_count_y_bounds: [0.0, 40.0],
                byte_count_y_bounds: [0.0, 50000.0],
                histogram_width_percentage: DEFAULT_HISTOGRAM_WIDTH_PERCENTAGE,
                zoom_context: ZoomContext::Packet,
                byte_counter_height_percentage: DEFAULT_BYTE_COUNTERS_HEIGHT_PERCENTAGE,
                autoscaling,
                interfaces_state,
            },
        }
    }
}

impl NetworkInterfaceModel {
    fn toggle_ebpf_program(&mut self, interface_index: u32, bpf: &mut aya::Ebpf) -> Result<()> {
        if let Some(is_loaded) = self.collecting.get(&interface_index) {
            if *is_loaded {
                let result = self.detach_ebpf_program(interface_index, bpf);
                if result.is_ok() {
                    self.collecting.insert(interface_index, false);
                }
                result
            } else {
                let result = self.attach_ebpf_program(interface_index, bpf);
                if result.is_ok() {
                    self.collecting.insert(interface_index, true);
                }
                result
            }
        } else {
            Err(eyre!(
                "Could not find an interface with index {} to toggle eBPF program on",
                interface_index
            ))
        }
    }

    fn find_interface(&self, interface_index: u32) -> Option<NetworkInterface> {
        let mut target_interface: Option<NetworkInterface> = None;
        for interface in &self.interfaces {
            if interface.index == interface_index {
                target_interface = Some(interface.clone());
                break;
            }
        }

        target_interface
    }

    fn attach_ebpf_program(&mut self, interface_index: u32, bpf: &mut aya::Ebpf) -> Result<()> {
        let interface = self.find_interface(interface_index);
        if let Some(interface) = interface {
            let program: &mut Xdp = bpf.program_mut("xdp_tsndt").unwrap().try_into()?;
            let xdp_link_id = program.attach(&interface.name, XdpFlags::default())
                .context("failed to attach the XDP program with default flags - try changing XdpFlags::default() to XdpFlags::SKB_MODE").unwrap();
            self.xdp_link_ids.insert(interface_index, xdp_link_id);
            let num_cpus = aya::util::nr_cpus().unwrap();

            let mut ebpf_interface_rx_counters: aya::maps::PerCpuHashMap<
                &mut MapData,
                u32,
                Counter,
            > = aya::maps::PerCpuHashMap::try_from(bpf.map_mut("INTERFACE_RX_COUNTERS").unwrap())
                .unwrap();
            if ebpf_interface_rx_counters.get(&interface.index, 0).is_err() {
                ebpf_interface_rx_counters.insert(
                    interface.index,
                    PerCpuValues::try_from(vec![
                        Counter {
                            bytes: 0,
                            packets: 0
                        };
                        num_cpus
                    ])?,
                    0,
                )?;
            }

            Ok(())
        } else {
            Err(eyre!(
                "Could not find an interface with index {} to attach eBPF program to",
                interface_index
            ))
        }
    }

    fn detach_ebpf_program(&mut self, interface_index: u32, bpf: &mut aya::Ebpf) -> Result<()> {
        let xdp_link_id = self.xdp_link_ids.remove(&interface_index);
        let num_cpus = aya::util::nr_cpus().unwrap();
        if let Some(xdp_link_id) = xdp_link_id {
            let program: &mut Xdp = bpf.program_mut("xdp_tsndt").unwrap().try_into()?;
            program.detach(xdp_link_id)
            .context("failed to attach the XDP program with default flags - try changing XdpFlags::default() to XdpFlags::SKB_MODE").unwrap();
            let mut ebpf_interface_rx_counters: aya::maps::PerCpuHashMap<
                &mut MapData,
                u32,
                Counter,
            > = aya::maps::PerCpuHashMap::try_from(bpf.map_mut("INTERFACE_RX_COUNTERS").unwrap())
                .unwrap();
            if ebpf_interface_rx_counters.get(&interface_index, 0).is_err() {
                ebpf_interface_rx_counters.insert(
                    interface_index,
                    PerCpuValues::try_from(vec![
                        Counter {
                            bytes: 0,
                            packets: 0
                        };
                        num_cpus
                    ])?,
                    0,
                )?;
            }
            self.tick_packet_count_data
                .insert(interface_index, vec![(0.0, 0.0); 1]);
            self.tick_byte_count_data
                .insert(interface_index, vec![(0.0, 0.0); 1]);
            Ok(())
        } else {
            Err(eyre!(
                "Could not find an interface with index {} to detach eBPF program from",
                interface_index
            ))
        }
    }

    fn on_tick(&mut self, bpf: &aya::Ebpf) -> Result<()> {
        self.tick_count += 1.0;

        let ebpf_interface_rx_counters: aya::maps::PerCpuHashMap<&MapData, u32, Counter> =
            aya::maps::PerCpuHashMap::try_from(bpf.map("INTERFACE_RX_COUNTERS").unwrap())?;

        let num_cpus =
            aya::util::nr_cpus().unwrap_or_else(|_| panic!("Could not get number of CPUs"));

        for interface in &self.interfaces {
            let result_val = ebpf_interface_rx_counters.get(&interface.index, 0)?;
            let packet_counts_window = self
                .tick_packet_count_data
                .get_mut(&interface.index)
                .unwrap();
            let byte_counts_window = self.tick_byte_count_data.get_mut(&interface.index).unwrap();
            let prev_packet_count_val = self.cumul_packet_counts.get(&interface.index).unwrap();
            let prev_byte_count_val = self.cumul_byte_counts.get(&interface.index).unwrap();

            if packet_counts_window.len() as f64 > self.window_size {
                packet_counts_window.remove(0);
            }

            if byte_counts_window.len() as f64 > self.window_size {
                byte_counts_window.remove(0);
            }

            // Sum up the value across all CPUs
            let mut across_cpus_packet_count: u32 = 0;
            let mut across_cpus_byte_count: u64 = 0;
            for cpu_id in 0..num_cpus {
                if let Some(cpu_counter) = result_val.get(cpu_id) {
                    across_cpus_packet_count += cpu_counter.packets;
                    across_cpus_byte_count += cpu_counter.bytes;
                }
            }

            packet_counts_window.push((
                self.tick_count,
                (across_cpus_packet_count - prev_packet_count_val) as f64,
            ));
            self.cumul_packet_counts
                .insert(interface.index, across_cpus_packet_count);

            byte_counts_window.push((
                self.tick_count,
                (across_cpus_byte_count - prev_byte_count_val) as f64,
            ));
            self.cumul_byte_counts
                .insert(interface.index, across_cpus_byte_count);
        }

        if self.tick_count > self.window_size {
            self.window[0] += 1.0;
            self.window[1] += 1.0;
        }

        Ok(())
    }
}

impl NetworkInterfaceView {
    fn draw(&mut self, frame: &mut Frame, model: &NetworkInterfaceModel, context_area: Rect) {
        let [iface_list, plots] =
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

        self.render_list(frame, iface_list, model);
        self.render_packet_time_series(frame, packet_time_series, model);
        self.render_packet_cumul_histogram(frame, packet_cumul_histogram, model);
        self.render_byte_time_series(frame, byte_time_series, model);
        self.render_byte_cumul_histogram(frame, byte_cumul_histogram, model);
    }

    fn render_packet_time_series(
        &mut self,
        frame: &mut Frame,
        area: Rect,
        model: &NetworkInterfaceModel,
    ) {
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
        let mut datasets = Vec::with_capacity(model.interfaces.len());
        let mut color_index = 1u8;
        for interface in &model.interfaces {
            let collecting = model.collecting.get(&interface.index);
            if let Some(collecting) = collecting {
                if *collecting {
                    let data = model.tick_packet_count_data.get(&interface.index).unwrap();
                    let iface_max_val = data.iter().max_by(|a, b| a.1.total_cmp(&b.1)).unwrap().1;
                    max_val = if max_val.total_cmp(&iface_max_val).is_ge() {
                        max_val
                    } else {
                        iface_max_val
                    };
                    let dataset = Dataset::default()
                        .name(interface.name.clone())
                        .marker(symbols::Marker::Dot)
                        .style(Style::default().fg(Color::Indexed(color_index)))
                        .data(data);
                    color_index += 1;
                    datasets.push(dataset);
                }
            } else {
                tracing::warn!(
                    "Could not find if interface with index {} was enabled or not",
                    interface.index
                );
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
        model: &NetworkInterfaceModel,
    ) {
        let mut target_interfaces: Vec<&NetworkInterface> =
            Vec::with_capacity(model.interfaces.len());
        for interface in &model.interfaces {
            let collecting = model.collecting.get(&interface.index);
            if let Some(collecting) = collecting {
                if *collecting {
                    target_interfaces.push(interface);
                }
            }
        }

        let mut data: Vec<(&str, u64)> = Vec::with_capacity(target_interfaces.len());

        for interface in target_interfaces {
            let val = model.cumul_packet_counts.get(&interface.index).unwrap();
            data.push((&interface.name, *val as u64));
        }

        data.sort_by_key(|datum| std::cmp::Reverse(datum.1));

        let bar_chart = BarChart::default()
            .block(Block::bordered().title("Cumulative packet count"))
            .bar_width(10)
            .data(&data);

        frame.render_widget(bar_chart, area);
    }

    fn render_byte_time_series(
        &mut self,
        frame: &mut Frame,
        area: Rect,
        model: &NetworkInterfaceModel,
    ) {
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
        let mut datasets = Vec::with_capacity(model.interfaces.len());
        let mut color_index = 1u8;
        for interface in &model.interfaces {
            let collecting = model.collecting.get(&interface.index);
            if let Some(collecting) = collecting {
                if *collecting {
                    let data = model.tick_byte_count_data.get(&interface.index).unwrap();
                    let iface_max_val = data.iter().max_by(|a, b| a.1.total_cmp(&b.1)).unwrap().1;
                    max_val = if max_val.total_cmp(&iface_max_val).is_ge() {
                        max_val
                    } else {
                        iface_max_val
                    };
                    let dataset = Dataset::default()
                        .name(interface.name.clone())
                        .marker(symbols::Marker::Dot)
                        .style(Style::default().fg(Color::Indexed(color_index)))
                        .data(data);
                    color_index += 1;
                    datasets.push(dataset);
                }
            } else {
                tracing::warn!(
                    "Could not find if interface with index {} was enabled or not",
                    interface.index
                );
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
            )
            .hidden_legend_constraints((Constraint::Min(0), Constraint::Min(0)))
            .legend_position(Some(LegendPosition::TopLeft));

        frame.render_widget(chart, area);
    }

    fn render_byte_cumul_histogram(
        &mut self,
        frame: &mut Frame,
        area: Rect,
        model: &NetworkInterfaceModel,
    ) {
        let mut target_interfaces: Vec<&NetworkInterface> =
            Vec::with_capacity(model.interfaces.len());
        for interface in &model.interfaces {
            let collecting = model.collecting.get(&interface.index);
            if let Some(collecting) = collecting {
                if *collecting {
                    target_interfaces.push(interface);
                }
            }
        }

        let mut data: Vec<(&str, u64)> = Vec::with_capacity(target_interfaces.len());

        for interface in target_interfaces {
            let val = model.cumul_byte_counts.get(&interface.index).unwrap();
            data.push((&interface.name, *val));
        }

        data.sort_by_key(|datum| std::cmp::Reverse(datum.1));

        let bar_chart = BarChart::default()
            .block(Block::bordered().title("Cumulative byte count"))
            .bar_width(10)
            .data(&data);

        frame.render_widget(bar_chart, area);
    }

    fn render_list(&mut self, frame: &mut Frame, list_area: Rect, model: &NetworkInterfaceModel) {
        let ifaces: Vec<ListItem> = model
            .interfaces
            .iter()
            .map(|iface| {
                let collecting = model.collecting.get(&iface.index);
                let color = if let Some(collecting) = collecting {
                    if *collecting {
                        Color::default()
                    } else {
                        DISABLED_COLOR
                    }
                } else {
                    DISABLED_COLOR
                };

                let li = ListItem::new(format!("{}: {}", iface.index, iface.name.clone()))
                    .style(Style::default().fg(color));
                li
            })
            .collect();

        let list = List::new(ifaces)
            .block(Block::bordered().title("Interface List"))
            .style(Style::new().white())
            .highlight_style(Style::new().italic())
            .highlight_symbol(">")
            .repeat_highlight_symbol(true)
            .direction(ListDirection::TopToBottom);

        frame.render_stateful_widget(list, list_area, &mut self.interfaces_state);
    }
}
