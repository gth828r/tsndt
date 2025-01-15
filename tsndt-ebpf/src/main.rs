#![no_std] //
#![no_main] //

use core::mem;

use aya_ebpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    maps::HashMap,
    programs::XdpContext,
};
use aya_log_ebpf::error;

// TODO: this should be made into a PerCpuHashMap. No need to deal with lock
// contention at sample time in the kernel since we can just sum the values
// from all CPUs on read without contention.
// See https://medium.com/@stevelatif/aya-rust-tutorial-part-5-using-maps-4d26c4a2fff8
#[map]
static INGRESS_PACKET_COUNTERS: HashMap<u32, u32> = HashMap::with_max_entries(1024, 0);

#[map]
static INGRESS_BYTE_COUNTERS: HashMap<u32, u64> = HashMap::with_max_entries(1024, 0);

#[xdp] //

pub fn xdp_tsndt(ctx: XdpContext) -> u32 {
    //

    match unsafe { try_xdp_tsndt(ctx) } {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

unsafe fn try_xdp_tsndt(ctx: XdpContext) -> Result<u32, u32> {
    //

    // Using a modified version of Aya for this, but I've asked about it
    // See https://github.com/aya-rs/aya/discussions/1130
    let index = ctx.ingress_ifindex() as u32;

    unsafe {
        let count = INGRESS_PACKET_COUNTERS.get_ptr_mut(&index);
        if let Some(count) = count {
            *count += 1;
        } else {
            let res = INGRESS_PACKET_COUNTERS.insert(&index, &1, 0);
            if let Err(e) = res {
                error!(&ctx, "Failed to insert new ingress packet counter value");
                return Err(e as u32);
            }
        }

        let byte_count = INGRESS_BYTE_COUNTERS.get_ptr_mut(&index);
        let packet_byte_count = (ctx.data_end() - ctx.data()) as u64;
        if let Some(byte_count) = byte_count {
            *byte_count += packet_byte_count;
        } else {
            let res = INGRESS_BYTE_COUNTERS.insert(&index, &packet_byte_count, 0);
            if let Err(e) = res {
                error!(&ctx, "Failed to insert new ingress byte counter value");
                return Err(e as u32);
            }
        }
    }

    //info!(&ctx, "received a packet on iface {}", index);
    //

    Ok(xdp_action::XDP_PASS)
}

#[inline(always)]
unsafe fn _ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return Err(());
    }

    Ok((start + offset) as *const T)
}

#[cfg(not(test))]
#[panic_handler] //

fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
