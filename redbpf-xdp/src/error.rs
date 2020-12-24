use core::result::Result as StdResult;

use cty::*;

pub type Result = StdResult<(), Errno>;

pub trait IntoResult {
    fn ok(&self) -> Result;
}

impl IntoResult for i32 {
    fn ok(&self) -> Result {
        if *self == 0 {
            Ok(())
        } else {
            Err(Errno(*self))
        }
    }
}

#[repr(transparent)]
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Errno(i32);

impl From<i32> for Errno {
    fn from(i: i32) -> Errno {
        Errno(i)
    }
}

impl From<Errno> for i32 {
    fn from(e: Errno) -> i32 {
        e.0
    }
}

impl PartialEq<i32> for Errno {
    fn eq(&self, other: &i32) -> bool {
        self.0 == *other
    }
}

impl Errno {
    pub fn last_os_error() -> Self {
        Errno(errno())
    }
}

pub fn errno() -> i32 {
    unsafe { *errno_location() }
}

extern "C" {
    #[cfg(not(target_os = "dragonfly"))]
    #[cfg_attr(
        any(target_os = "macos", target_os = "ios", target_os = "freebsd"),
        link_name = "__error"
    )]
    #[cfg_attr(
        any(
            target_os = "openbsd",
            target_os = "netbsd",
            target_os = "bitrig",
            target_os = "android"
        ),
        link_name = "__errno"
    )]
    #[cfg_attr(
        any(target_os = "solaris", target_os = "illumos"),
        link_name = "___errno"
    )]
    #[cfg_attr(target_os = "linux", link_name = "__errno_location")]
    fn errno_location() -> *mut c_int;
}

#[cfg(feature = "use_std")]
impl std::fmt::Display for Errno {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.write_str(&self.reason().expect("reason"))
    }
}

#[cfg(feature = "use_std")]
impl Errno {
    pub fn reason(&self) -> StdResult<String, Errno> {
        let mut buf = [0; 1024];
        unsafe {
            if libc::strerror_r(self.0, buf.as_mut_ptr(), buf.len() as libc::size_t) < 0 {
                return Err(Errno::last_os_error());
            }
        }
        let c_str = unsafe { std::ffi::CStr::from_ptr(buf.as_ptr()) };
        Ok(String::from_utf8_lossy(c_str.to_bytes()).to_string())
    }
}
