#![no_std] //
#![no_main] //

use core::mem;

use aya_ebpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    maps::{LruPerCpuHashMap, PerCpuHashMap},
    programs::XdpContext,
};
use aya_log_ebpf::error;
use network_types::eth::EthHdr;

const MAX_NUM_INTERFACES: u32 = 1024;
const MAX_NUM_MAC_ADDRS: u32 = 8192;

#[map]
static INTERFACE_RX_PACKET_COUNTERS: PerCpuHashMap<u32, u32> =
    PerCpuHashMap::with_max_entries(MAX_NUM_INTERFACES, 0);

#[map]
static INTERFACE_RX_BYTE_COUNTERS: PerCpuHashMap<u32, u64> =
    PerCpuHashMap::with_max_entries(MAX_NUM_INTERFACES, 0);

#[map]
static SRC_MAC_RX_PACKET_COUNTERS: LruPerCpuHashMap<[u8; 6], u32> =
    LruPerCpuHashMap::with_max_entries(MAX_NUM_MAC_ADDRS, 0);

#[map]
static SRC_MAC_RX_BYTE_COUNTERS: LruPerCpuHashMap<[u8; 6], u64> =
    LruPerCpuHashMap::with_max_entries(MAX_NUM_MAC_ADDRS, 0);

#[xdp]
pub fn xdp_tsndt(ctx: XdpContext) -> u32 {
    match unsafe { try_xdp_tsndt(ctx) } {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

unsafe fn try_xdp_tsndt(ctx: XdpContext) -> Result<u32, u32> {
    // Using a modified version of Aya for this, but I've asked about it
    // See https://github.com/aya-rs/aya/discussions/1130
    let index = ctx.ingress_ifindex() as u32;

    unsafe {
        let count = INTERFACE_RX_PACKET_COUNTERS.get_ptr_mut(&index);
        if let Some(count) = count {
            *count += 1;
        } else {
            let res = INTERFACE_RX_PACKET_COUNTERS.insert(&index, &1, 0);
            if let Err(e) = res {
                error!(&ctx, "Failed to insert new ingress packet counter value");
                return Err(e as u32);
            }
        }

        let byte_count = INTERFACE_RX_BYTE_COUNTERS.get_ptr_mut(&index);
        let packet_byte_count = (ctx.data_end() - ctx.data()) as u64;
        if let Some(byte_count) = byte_count {
            *byte_count += packet_byte_count;
        } else {
            let res = INTERFACE_RX_BYTE_COUNTERS.insert(&index, &packet_byte_count, 0);
            if let Err(e) = res {
                error!(&ctx, "Failed to insert new ingress byte counter value");
                return Err(e as u32);
            }
        }

        let tmp = ptr_at(&ctx, 0);
        let eth_hdr: *const EthHdr = if tmp.is_ok() {
            tmp.unwrap()
        } else {
            return Err(0);
        };

        let src_mac = (*eth_hdr).src_addr;

        let count = SRC_MAC_RX_PACKET_COUNTERS.get_ptr_mut(&src_mac);
        if let Some(count) = count {
            *count += 1;
        } else {
            let res = SRC_MAC_RX_PACKET_COUNTERS.insert(&src_mac, &1, 0);
            if let Err(e) = res {
                error!(
                    &ctx,
                    "Failed to insert new ingress source MAC packet counter value"
                );
                return Err(e as u32);
            }
        }

        let byte_count = SRC_MAC_RX_BYTE_COUNTERS.get_ptr_mut(&src_mac);
        let packet_byte_count = (ctx.data_end() - ctx.data()) as u64;
        if let Some(byte_count) = byte_count {
            *byte_count += packet_byte_count;
        } else {
            let res = SRC_MAC_RX_BYTE_COUNTERS.insert(&src_mac, &packet_byte_count, 0);
            if let Err(e) = res {
                error!(
                    &ctx,
                    "Failed to insert new ingress source MAC byte counter value"
                );
                return Err(e as u32);
            }
        }
    }

    Ok(xdp_action::XDP_PASS)
}

#[inline(always)]
unsafe fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return Err(());
    }

    Ok((start + offset) as *const T)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
