use core::mem;
use core::result::Result as StdResult;

use redbpf_probes::net::NetworkBuffer;

use crate::net::{Error, EthHdr, Header};
use crate::xdp::Context;

type Result<T> = StdResult<T, Error>;

pub trait Buffer: NetworkBuffer {
    #[inline]
    unsafe fn header_at<T>(&self, addr: usize) -> Result<Header<T>> {
        self.check_bounds(addr, addr + mem::size_of::<T>())?;

        Ok(Header::new_unchecked(addr as *const T as *mut T))
    }

    #[inline]
    unsafe fn header_after<T, H>(&self, hdr: &Header<T>) -> Result<Header<H>> {
        self.header_at(hdr.as_ptr().add(1) as usize)
    }

    /// Returns the packet's `Ethernet` header if present.
    #[inline]
    fn eth_hdr(&self) -> Result<EthHdr> {
        unsafe { self.header_at(self.data_start() as usize) }
    }
}

impl Buffer for Context {}
