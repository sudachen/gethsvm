// Copyright 2017 (c) ETCDEV Team

use bigint::{Gas, U256, H256, M256, Address};
use std::ptr;
use std::slice;
use std::rc::Rc;

#[repr(C)]
#[derive(Copy)]
pub struct Ptr(*const u8);

impl Ptr {
    pub fn is_null(self) -> bool {
        return self.0.is_null()
    }
    pub fn raw(self) -> Option<*const u8> {
        return if self.0.is_null() { None } else { Some(self.0) }
    }
}

impl Clone for Ptr {
    fn clone(&self) -> Ptr { *self }
}

pub fn address_from_bits( ptr: *const u8 ) -> Address {
    if ptr.is_null() {
        Address::from(0u64)
    } else {
        Address::from(unsafe { slice::from_raw_parts(ptr, 20) })
    }
}
impl Into<Address> for Ptr {
    fn into(self) -> Address {
        address_from_bits(self.0)
    }
}

impl Into<Option<Address>> for Ptr {
    fn into(self) -> Option<Address> {
        self.raw().map(|ptr|address_from_bits(ptr))
    }
}

pub fn u256_from_bits( ptr: *const u8 ) -> U256 {
    if ptr.is_null() {
        U256::zero()
    } else {
        let mut ret = [0u64; 4];
        let bytes = unsafe { slice::from_raw_parts(ptr, 32) };
        for i in 0..bytes.len() {
            let pos = i / 8;
            ret[pos] += (bytes[i] as u64) << ((i % 8) * 8);
        }
        U256(ret)
    }
}

impl Into<U256> for Ptr {
    fn into(self) -> U256 {
        u256_from_bits(self.0)
    }
}

#[allow(dead_code)]
pub fn gas_from_bits( ptr: *const u8 ) -> Gas {
    u256_from_bits(ptr).into()
}

impl Into<Gas> for Ptr {
    fn into(self) -> Gas {
        u256_from_bits(self.0).into()
    }
}

pub fn h256_from_bits( ptr: *const u8 ) -> H256 {
    if ptr.is_null() {
        H256::zero()
    } else {
        let mut ret = [0u8; 32];
        unsafe { ptr::copy(ptr, &mut ret[0], 32) }
        H256(ret)
    }
}

impl Into<H256> for Ptr {
    fn into(self) -> H256 {
        h256_from_bits(self.0)
    }
}

#[allow(dead_code)]
pub fn m256_from_bits( ptr: *const u8 ) -> M256 {
    u256_from_bits(ptr).into()
}

impl Into<M256> for Ptr {
    fn into(self) -> M256 {
        u256_from_bits(self.0).into()
    }
}

pub fn vec_from_bits( ptr: *const u8, len: usize ) -> Vec<u8> {
    if ptr.is_null() || len == 0 {
        Vec::with_capacity(0)
    } else {
        let mut v: Vec<u8> = Vec::with_capacity(len);
        unsafe {
            v.set_len(len);
            ptr::copy(ptr, &mut v[0], len);
        }
        v
    }
}

pub fn rcv_from_bits( ptr: Ptr, len: usize ) -> Rc<Vec<u8>> {
    Rc::new(vec_from_bits(ptr.0,len))
}
