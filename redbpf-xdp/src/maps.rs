use core::marker::PhantomData;
use core::mem;
use core::ops::{Deref, DerefMut, Index, IndexMut};
use core::ptr::NonNull;

use redbpf_probes::{bindings::*, helpers::*};

use crate::error::{IntoResult, Result};

pub use redbpf_probes::maps::{PerfMap, PerfMapFlags};

macro_rules! map_type {
    ($name:ident<T> : array [ $ty:expr ]) => {
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

        impl<T> AsRef<bpf_map_def> for $name<T> {
            fn as_ref(&self) -> &bpf_map_def {
                &self.def
            }
        }

        impl<T> $name<T> {
            pub const fn with_max_entries(max_entries: u32) -> Self {
                Self(GenericArray::with_max_entries($ty, max_entries))
            }
        }
    };

    ($name:ident < $value:ty > : array [ $ty:expr ]) => {
        #[repr(transparent)]
        pub struct $name(GenericArray<$value>);

        impl Deref for $name {
            type Target = GenericArray<$value>;

            fn deref(&self) -> &Self::Target {
                &self.0
            }
        }

        impl DerefMut for $name {
            fn deref_mut(&mut self) -> &mut Self::Target {
                &mut self.0
            }
        }

        impl AsRef<bpf_map_def> for $name {
            fn as_ref(&self) -> &bpf_map_def {
                &self.def
            }
        }

        impl $name {
            pub const fn with_max_entries(max_entries: u32) -> Self {
                Self(GenericArray::with_max_entries($ty, max_entries))
            }
        }
    };

    ($name:ident<K, V> : hashmap [ $ty:expr ]) => {
        #[repr(transparent)]
        pub struct $name<K, V>(GenericHashMap<K, V>);

        impl<K, V> Deref for $name<K, V> {
            type Target = GenericHashMap<K, V>;

            fn deref(&self) -> &Self::Target {
                &self.0
            }
        }

        impl<K, V> DerefMut for $name<K, V> {
            fn deref_mut(&mut self) -> &mut Self::Target {
                &mut self.0
            }
        }

        impl<K, V> AsRef<bpf_map_def> for $name<K, V> {
            fn as_ref(&self) -> &bpf_map_def {
                &self.def
            }
        }

        impl<K, V> $name<K, V> {
            pub const fn with_max_entries(max_entries: u32) -> Self {
                Self(GenericHashMap::with_max_entries($ty, max_entries))
            }
        }
    };
}

map_type!(Array<T>: array[bpf_map_type_BPF_MAP_TYPE_ARRAY]);
map_type!(ProgArray<T>: array[bpf_map_type_BPF_MAP_TYPE_PROG_ARRAY]);
map_type!(PerCpuArray<T>: array[bpf_map_type_BPF_MAP_TYPE_PERCPU_ARRAY]);
map_type!(ArrayOfMaps<u32>: array[bpf_map_type_BPF_MAP_TYPE_ARRAY_OF_MAPS]);
map_type!(HashMap<K, V>: hashmap[bpf_map_type_BPF_MAP_TYPE_HASH]);
map_type!(PerCpuHashMap<K, V>: hashmap[bpf_map_type_BPF_MAP_TYPE_PERCPU_HASH]);
map_type!(LruHashMap<K, V>: hashmap[bpf_map_type_BPF_MAP_TYPE_LRU_HASH]);
map_type!(LruPerCpuHashMap<K, V>: hashmap[bpf_map_type_BPF_MAP_TYPE_LRU_PERCPU_HASH]);

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
    /// Creates a generic array with the specified maximum number of elements.
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
    pub fn get(&self, index: u32) -> Option<&T> {
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

impl ArrayOfMaps {
    #[inline(always)]
    pub fn get<M>(&mut self, index: u32) -> Option<&M>
    where
        M: AsRef<bpf_map_def>,
    {
        unsafe { self.lookup(index).map(|item| &*item.as_ptr().cast()) }
    }

    #[inline(always)]
    pub fn get_mut<M>(&mut self, index: u32) -> Option<&mut M>
    where
        M: AsRef<bpf_map_def>,
    {
        unsafe { self.lookup(index).map(|item| &mut *item.as_ptr().cast()) }
    }
}

#[repr(transparent)]
pub struct GenericHashMap<K, V> {
    def: bpf_map_def,
    key: PhantomData<K>,
    value: PhantomData<V>,
}

impl<K, V> GenericHashMap<K, V> {
    /// Creates a generic hashmap with the specified maximum number of elements.
    const fn with_max_entries(ty: u32, max_entries: u32) -> Self {
        Self {
            def: bpf_map_def {
                type_: ty,
                key_size: mem::size_of::<K>() as u32,
                value_size: mem::size_of::<V>() as u32,
                max_entries,
                map_flags: 0,
            },
            key: PhantomData,
            value: PhantomData,
        }
    }

    #[inline(always)]
    pub fn get(&self, key: &K) -> Option<&V> {
        unsafe { self.lookup(key).map(|item| &*item.as_ptr()) }
    }

    #[inline(always)]
    pub fn get_mut(&mut self, key: &K) -> Option<&mut V> {
        unsafe { self.lookup(key).map(|item| &mut *item.as_ptr()) }
    }

    #[inline(always)]
    unsafe fn lookup(&self, key: &K) -> Option<NonNull<V>> {
        NonNull::new(bpf_map_lookup_elem(
            &self.def as *const _ as *mut bpf_map_def as *mut _,
            key as *const _ as *const _,
        ) as *mut _)
    }

    /// Set the `value` in the map for `key`
    #[inline(always)]
    pub fn set(&mut self, key: &K, value: &V) -> Result {
        unsafe {
            bpf_map_update_elem(
                &mut self.def as *mut _ as *mut _,
                key as *const _ as *const _,
                value as *const _ as *const _,
                BPF_ANY as u64,
            )
        }
        .ok()
    }

    /// Delete the entry indexed by `key`
    #[inline]
    pub fn delete(&mut self, key: &K) -> Result {
        unsafe {
            bpf_map_delete_elem(
                &mut self.def as *mut _ as *mut _,
                key as *const _ as *const _,
            )
        }
        .ok()
    }
}
