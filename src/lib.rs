
extern crate sputnikvm;
extern crate hexutil;
extern crate bigint;
extern crate libc;
extern crate block_core;
extern crate block;

use libc::{c_void,c_char};

use std::mem;
use std::ffi::{CStr,CString};
use std::rc::Rc;
use std::ptr;
use std::str::FromStr;

use bigint::{Gas, M256, U256, H256, Address};
use hexutil::*;
use block::TransactionAction;
use sputnikvm::errors::RequireError;
use sputnikvm::{VM, SeqTransactionVM, HeaderParams, MainnetEIP160Patch, ValidTransaction, SeqContextVM, AccountCommitment, Context, AccountChange, Storage, Patch, VMStatus};

#[no_mangle]
pub extern fn sputnikvm_is_implemented() -> i32 {
  1
}

fn address_from_ptr( ptr: *const c_char ) -> Address {
    Address::from_str(unsafe{CStr::from_ptr(ptr)}.to_str().unwrap()).unwrap()
}

fn gas_from_ptr( ptr: *const c_char ) -> Gas {
    Gas::from_str(unsafe{CStr::from_ptr(ptr)}.to_str().unwrap()).unwrap()
}

fn u256_from_ptr( ptr: *const c_char ) -> U256 {
    U256::from_str(unsafe{CStr::from_ptr(ptr)}.to_str().unwrap()).unwrap()
}

pub struct EvmContext {
    vm : Box<VM>,
    req_blocknum : u64,
    req_address : CString,
    req_hash : CString,
}

#[no_mangle]
pub extern fn sputnikvm_context(
    create_new: i32,
    gas: *const c_char,
    price: *const c_char,
    value: *const c_char,
    caller: *const c_char,
    target: *const c_char,
    bytes: *mut u8,
    bytes_len: usize,
    gas_limit: *const c_char,
    coinbase: *const c_char,
    fork: i32,
    blocknum: *const c_char,
    time: u64,
    difficulty: *const c_char) -> *mut EvmContext {

    let input = unsafe { Vec::from_raw_parts(bytes, bytes_len, bytes_len) };

    fn new_vm( t: ValidTransaction, p: HeaderParams ) -> Box<VM> {
        Box::new(SeqTransactionVM::<MainnetEIP160Patch>::new(t,p))
    };

    let vm_impl = new_vm(
        ValidTransaction {
            caller: Some(address_from_ptr(caller)),
            gas_price: gas_from_ptr(price),
            gas_limit: gas_from_ptr(gas),
            action: if create_new != 0 { TransactionAction::Create } else { TransactionAction::Call(address_from_ptr(target)) },
            value: u256_from_ptr(value),
            input: Rc::new(input),
            nonce: U256::zero(),
        },
        HeaderParams {
            beneficiary: address_from_ptr(coinbase),
            timestamp: time,
            number: u256_from_ptr(blocknum),
            difficulty: u256_from_ptr(difficulty),
            gas_limit: gas_from_ptr(gas_limit),
        });

    let mut ctx = Box::new(EvmContext {
        vm : vm_impl,
        req_blocknum : 0,
        req_address : CString::new("").unwrap(),
        req_hash : CString::new("").unwrap(),
    });

    let ptr: *mut _ = &mut *ctx;
    ::std::mem::forget(ctx);
    ptr
}

const SPUTNIK_VM_EXITED : i32 = 0;
const SPUTNIK_VM_REQUIRE_ACCOUNT : i32 = 2;
const SPUTNIK_VM_REQUIRE_CODE : i32 = 3;
const SPUTNIK_VM_REQUIRE_HASH : i32 = 4;
const SPUTNIK_VM_REQUIRE_VALUE : i32 = 5;

#[no_mangle]
pub extern fn sputnikvm_fire(ptr: *mut EvmContext) -> i32 {
    let ctx = unsafe{&mut *ptr};
    match ctx.vm.fire() {
        Err(RequireError::Account(address)) => {
            ctx.req_address = CString::new(format!("0x{:x}",address)).unwrap();
            SPUTNIK_VM_REQUIRE_ACCOUNT
        },
        Err(RequireError::AccountCode(address)) => {
            ctx.req_address = CString::new(format!("0x{:x}",address)).unwrap();
            SPUTNIK_VM_REQUIRE_CODE
        },
        Err(RequireError::AccountStorage(address, index)) => {
            ctx.req_address = CString::new(format!("0x{:x}",address)).unwrap();
            ctx.req_hash = CString::new(format!("0x{:x}",index)).unwrap();
            SPUTNIK_VM_REQUIRE_VALUE
        },
        Err(RequireError::Blockhash(number)) => {
            ctx.req_blocknum = number.as_u64();
            SPUTNIK_VM_REQUIRE_HASH
        },
        Ok(()) => SPUTNIK_VM_EXITED,
    }
}

#[no_mangle]
pub extern fn sputnikvm_req_address(ptr: *mut EvmContext) -> *const c_char {
    let ctx = unsafe{&*ptr};
    ctx.req_address.as_ptr()
}

#[no_mangle]
pub extern fn sputnikvm_req_hash(ptr: *mut EvmContext) -> *const c_char {
    let ctx = unsafe{&*ptr};
    ctx.req_hash.as_ptr()
}

#[no_mangle]
pub extern fn sputnikvm_req_blocknum(ptr: *mut EvmContext) -> u64 {
    let ctx = unsafe{&*ptr};
    ctx.req_blocknum
}

static EMPTY: [u8; 0] = [];

#[no_mangle]
pub extern fn sputnikvm_commit_account(
    ptr: *mut EvmContext,
    addr_ptr: *const c_char,
    nonce: u64,
    balance_ptr: *const c_char,
    bytes: *mut u8,
    bytes_len: usize) {

    let ctx = unsafe{&mut *ptr};

    if balance_ptr.is_null() {
        ctx.vm.commit_account(AccountCommitment::Full {
            address: address_from_ptr(addr_ptr),
            balance: U256::zero(),
            code: Rc::new(EMPTY.as_ref().into()),
            nonce: U256::zero(),
        });
    } else {
        let code = if bytes.is_null() {
            EMPTY.as_ref().into()
        } else {
            unsafe { Vec::from_raw_parts(bytes, bytes_len, bytes_len) }
        };
        ctx.vm.commit_account(AccountCommitment::Full {
            address: address_from_ptr(addr_ptr),
            balance: u256_from_ptr(balance_ptr),
            code: Rc::new(code),
            nonce: nonce.into(),
        });
    }
}

#[no_mangle]
pub extern fn sputnikvm_commit_code(
    ptr: *mut EvmContext,
    addr_ptr: *const c_char,
    bytes: *mut u8,
    bytes_len: usize) {

    let ctx = unsafe{&mut *ptr};
    let code = if bytes.is_null() {
        EMPTY.as_ref().into()
    } else {
        unsafe { Vec::from_raw_parts(bytes, bytes_len, bytes_len) }
    };

    ctx.vm.commit_account(AccountCommitment::Code {
        address: address_from_ptr(addr_ptr),
        code: Rc::new(code),
    });
}
