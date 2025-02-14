#![no_std]

#[repr(C)]
#[derive(Clone, Copy)]
pub struct Counter {
    pub bytes: u64,
    pub packets: u32,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for Counter {}
