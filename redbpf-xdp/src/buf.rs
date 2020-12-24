use core::mem;
use core::result::Result as StdResult;

use redbpf_probes::net::NetworkBuffer;

use crate::net::{Error, Ethernet, Layer};
use crate::xdp::Context;

type Result<T> = StdResult<T, Error>;

pub trait Buffer: NetworkBuffer {
    #[inline]
    unsafe fn layer_at<T>(&self, addr: usize) -> Result<Layer<T>> {
        self.check_bounds(addr, addr + mem::size_of::<T>())?;

        Ok(Layer::new_unchecked(addr as *const T as *mut T))
    }

    #[inline]
    unsafe fn layer_after<T, H>(&self, hdr: &Layer<T>) -> Result<Layer<H>> {
        self.layer_at(hdr.as_ptr().add(1) as usize)
    }

    /// Returns the packet's `Ethernet` header if present.
    #[inline]
    fn ethernet(&self) -> Result<Ethernet> {
        unsafe { self.layer_at(self.data_start() as usize) }
    }
}

impl Buffer for Context {}
