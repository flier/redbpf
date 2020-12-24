use core::marker::PhantomData;
use core::mem;
use core::ops::{Deref, DerefMut, Index, IndexMut};
use core::ptr::NonNull;

use redbpf_probes::{bindings::*, helpers::*};

use crate::error::{IntoResult, Result};

pub use redbpf_probes::maps::{HashMap, PerfMap, PerfMapFlags};

macro_rules! array_type {
    ($name:ident, $ty:expr) => {
        #[repr(transparent)]
        pub struct $name<T>(GenericArray<T>);

        impl<T> Deref for $name<T> {
            type Target = GenericArray<T>;

            fn deref(&self) -> &Self::Target {
                &self.0
            }
        }

        impl<T> DerefMut for $name<T> {
            fn deref_mut(&mut self) -> &mut Self::Target {
                &mut self.0
            }
        }

        impl<T> $name<T> {
            pub const fn with_max_entries(max_entries: u32) -> Self {
                Self(GenericArray::with_max_entries($ty, max_entries))
            }
        }
    };
}

array_type!(Array, bpf_map_type_BPF_MAP_TYPE_ARRAY);
array_type!(ProgArray, bpf_map_type_BPF_MAP_TYPE_PROG_ARRAY);
array_type!(PerCpuArray, bpf_map_type_BPF_MAP_TYPE_PERCPU_ARRAY);

#[repr(transparent)]
pub struct GenericArray<T> {
    def: bpf_map_def,
    item: PhantomData<T>,
}

impl<T> Index<u32> for GenericArray<T> {
    type Output = T;

    fn index(&self, index: u32) -> &Self::Output {
        unsafe { &*self.lookup(index).unwrap().as_ptr() }
    }
}

impl<T> IndexMut<u32> for GenericArray<T> {
    fn index_mut(&mut self, index: u32) -> &mut Self::Output {
        unsafe { &mut *self.lookup(index).unwrap().as_ptr() }
    }
}

impl<T> GenericArray<T> {
    /// Creates a per CPU array with the specified maximum number of elements.
    const fn with_max_entries(ty: u32, max_entries: u32) -> Self {
        Self {
            def: bpf_map_def {
                type_: ty,
                key_size: mem::size_of::<u32>() as u32,
                value_size: mem::size_of::<T>() as u32,
                max_entries,
                map_flags: 0,
            },
            item: PhantomData,
        }
    }

    #[inline(always)]
    pub fn get(&mut self, index: u32) -> Option<&T> {
        unsafe { self.lookup(index).map(|item| &*item.as_ptr()) }
    }

    #[inline(always)]
    pub fn get_mut(&mut self, index: u32) -> Option<&mut T> {
        unsafe { self.lookup(index).map(|item| &mut *item.as_ptr()) }
    }

    /// Set the `value` in the map for `key`
    #[inline(always)]
    pub fn set(&mut self, index: u32, value: &T) -> Result {
        unsafe {
            bpf_map_update_elem(
                &mut self.def as *mut _ as *mut _,
                &index as *const _ as *const _,
                value as *const _ as *const _,
                BPF_ANY as u64,
            )
        }
        .ok()
    }

    #[inline(always)]
    unsafe fn lookup(&self, index: u32) -> Option<NonNull<T>> {
        NonNull::new(bpf_map_lookup_elem(
            &self.def as *const _ as *mut bpf_map_def as *mut _,
            &index as *const _ as *const _,
        ) as *mut _)
    }
}
