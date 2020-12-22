// Copyright 2019 Authors of Red Sift
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.
use core::convert::TryFrom;
use core::mem;
use core::ops::{Deref, DerefMut};
use core::ptr::NonNull;

use crate::bindings::*;
use crate::xdp::Context;

pub use crate::buf::Buffer;
pub use redbpf_probes::net::NetworkError as Error;

pub const BE_ETH_P_IP: __be16 = (ETH_P_IP as u16).to_be();
pub const BE_ETH_P_IPV6: __be16 = (ETH_P_IPV6 as u16).to_be();

mod addr {
    use crate::bindings::*;

    pub trait Element
    where
        Self: Sized,
    {
        unsafe fn as_slice(addr: &in6_addr) -> &[Self];

        unsafe fn as_mut_slice(addr: &mut in6_addr) -> &mut [Self];
    }

    impl Element for u8 {
        unsafe fn as_slice(addr: &in6_addr) -> &[Self] {
            &addr.in6_u.u6_addr8[..]
        }

        unsafe fn as_mut_slice(addr: &mut in6_addr) -> &mut [Self] {
            &mut addr.in6_u.u6_addr8[..]
        }
    }

    impl Element for __be16 {
        unsafe fn as_slice(addr: &in6_addr) -> &[Self] {
            &addr.in6_u.u6_addr16[..]
        }

        unsafe fn as_mut_slice(addr: &mut in6_addr) -> &mut [Self] {
            &mut addr.in6_u.u6_addr16[..]
        }
    }

    impl Element for __be32 {
        unsafe fn as_slice(addr: &in6_addr) -> &[Self] {
            &addr.in6_u.u6_addr32[..]
        }

        unsafe fn as_mut_slice(addr: &mut in6_addr) -> &mut [Self] {
            &mut addr.in6_u.u6_addr32[..]
        }
    }

    impl<T> AsRef<[T]> for in6_addr
    where
        T: Element,
    {
        fn as_ref(&self) -> &[T] {
            unsafe { T::as_slice(self) }
        }
    }

    impl<T> AsMut<[T]> for in6_addr
    where
        T: Element,
    {
        fn as_mut(&mut self) -> &mut [T] {
            unsafe { T::as_mut_slice(self) }
        }
    }
}

#[repr(transparent)]
#[derive(Copy, Clone, PartialEq, PartialOrd)]
pub struct Header<T>(NonNull<T>);

impl<T> Deref for Header<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        unsafe { self.0.as_ref() }
    }
}

impl<T> DerefMut for Header<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        unsafe { self.0.as_mut() }
    }
}

impl<T> TryFrom<*const T> for Header<T> {
    type Error = Error;

    fn try_from(header: *const T) -> Result<Header<T>, Self::Error> {
        Self::new(header as *mut _).ok_or(Error::Other)
    }
}

impl<T> TryFrom<*mut T> for Header<T> {
    type Error = Error;

    fn try_from(header: *mut T) -> Result<Header<T>, Self::Error> {
        Self::new(header).ok_or(Error::Other)
    }
}

impl<T> Header<T> {
    pub fn new(ptr: *mut T) -> Option<Self> {
        NonNull::new(ptr).map(Self)
    }

    pub unsafe fn new_unchecked(ptr: *mut T) -> Self {
        Self(NonNull::new_unchecked(ptr))
    }

    pub fn as_ptr(&self) -> *mut T {
        self.0.as_ptr()
    }

    pub fn next<H>(&self, ctx: &Context) -> Result<Header<H>, Error> {
        unsafe { ctx.header_after(self) }
    }
}

pub type EthHdr = Header<ethhdr>;
pub type IPHdr = Header<iphdr>;
pub type IPv6Hdr = Header<ipv6hdr>;
pub type IcmpHdr = Header<icmphdr>;
pub type Icmp6Hdr = Header<icmp6hdr>;
pub type TcpHdr = Header<tcphdr>;
pub type UdpHdr = Header<udphdr>;

impl EthHdr {
    pub fn proto(&self) -> u16 {
        u16::from(self.h_proto)
    }

    pub fn swap_addr(&mut self) {
        let eth = unsafe { self.0.as_mut() };
        mem::swap(&mut eth.h_source, &mut eth.h_dest);
    }
}

impl IPHdr {
    pub fn fragmented(&self) -> bool {
        (self.frag_off & 0x3FFF) != 0
    }

    pub fn swap_addr(&mut self) {
        let iph = unsafe { self.0.as_mut() };
        mem::swap(&mut iph.saddr, &mut iph.daddr);
    }
}

impl IPv6Hdr {
    pub fn traffic_class(&self) -> u8 {
        ((self.priority() << 4) & 0xF0) | ((self.flow_lbl[0] >> 4) & 0x0F)
    }

    pub fn swap_addr(&mut self) {
        let ip6h = unsafe { self.0.as_mut() };
        mem::swap(&mut ip6h.saddr, &mut ip6h.daddr);
    }
}
