use core::mem;
use core::ptr;
use core::slice;

use redbpf_probes::helpers::bpf_csum_diff;

use crate::bindings::*;
use crate::net::IPv4;

impl IPv4 {
    pub fn compute_checksum(&mut self) {
        self.check = 0;
        self.check = ipv4_csum_inline(self.as_ptr(), 0);
    }
}

#[inline(always)]
fn csum_fold_helper(mut csum: u64) -> u16 {
    for _ in 0..4 {
        let n = csum >> 16;
        if n != 0 {
            csum = (csum & 0xffff) + n;
        }
    }
    !csum as u16
}

#[inline(always)]
fn ipv4_csum<T>(data: *mut T, csum: &mut u64) {
    *csum = unsafe {
        bpf_csum_diff(
            ptr::null_mut(),
            0,
            data as *mut _,
            mem::size_of::<T> as u32,
            *csum as u32,
        ) as u64
    };
    *csum = csum_fold_helper(*csum) as u64;
}

#[inline(always)]
fn ipv4_csum_inline(iph: *const iphdr, csum: u64) -> __sum16 {
    let data = unsafe {
        slice::from_raw_parts(
            iph as *const __be16,
            mem::size_of::<iphdr>() / mem::size_of::<__be16>(),
        )
    };
    let csum = data.iter().fold(csum, |csum, n| csum + *n as u64);
    csum_fold_helper(csum)
}
