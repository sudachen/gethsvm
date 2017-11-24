
extern crate sputnikvm;
extern crate hexutil;
extern crate bigint;
extern crate libc;
extern crate block_core;
extern crate block;

use std::mem::{drop,forget};
use std::ffi::{CStr,CString};
use std::rc::Rc;
use std::ptr;
use std::str::FromStr;

use libc::{c_char,size_t};
use bigint::{Gas, H160, U256, H256, M256, Address};
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

fn h256_from_ptr( ptr: *const c_char ) -> H256 {
    H256::from_str(unsafe{CStr::from_ptr(ptr)}.to_str().unwrap()).unwrap()
}

fn m256_from_ptr( ptr: *const c_char ) -> M256 {
    M256::from_str(unsafe{CStr::from_ptr(ptr)}.to_str().unwrap()).unwrap()
}

struct Accounts {
    list : Vec<*const AccountChange>,
    index: usize
}

impl Accounts {
    fn next(&mut self) -> Option<*const AccountChange> {
        if self.index < self.list.len() { self.index+=1; Some(self.list[self.index])} else {None}
    }
}

pub struct EvmContext {
    vm : Box<VM>,
    req_blocknum : u64,
    req_address : CString,
    req_hash : CString,
    out : CString,
    out_len : usize,
    account : Accounts
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
        out : CString::new("").unwrap(),
        out_len : 0,
        account: Accounts{list: Vec::new(), index: 0},
    });

    let ptr: *mut _ = &mut *ctx;
    forget(ctx);
    ptr
}

#[no_mangle]
pub extern fn sputnikvm_terminate(ptr: *mut EvmContext) {
    drop(ptr)
}

const SPUTNIK_VM_EXITED_OK : i32 = 0;
const SPUTNIK_VM_EXITED_ERR : i32 = 1;
const SPUTNIK_VM_RUNNING : i32 = 2;
const SPUTNIK_VM_UNSUPPORTED_ERR : i32 = 3;

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
        Ok(()) => SPUTNIK_VM_EXITED_OK,
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

#[no_mangle]
pub extern fn sputnikvm_commit_blockhash(
    ptr: *mut EvmContext,
    number: u64,
    hash_ptr: *const c_char) {

    let ctx = unsafe{&mut *ptr};
    ctx.vm.commit_blockhash(number.into(), h256_from_ptr(hash_ptr));
}

#[no_mangle]
pub extern fn sputnikvm_commit_value(
    ptr: *mut EvmContext,
    addr_ptr: *const c_char,
    key_ptr: *const c_char,
    value_ptr: *const c_char) {

    let ctx = unsafe{&mut *ptr};
    ctx.vm.commit_account(AccountCommitment::Storage {
        address: address_from_ptr(addr_ptr),
        index: u256_from_ptr(key_ptr),
        value: m256_from_ptr(value_ptr),
    });

}

#[no_mangle]
pub extern fn sputnikvm_out(ptr: *mut EvmContext) -> *const c_char {
    let ctx = unsafe{&mut *ptr};
    let v = ctx.vm.out().to_vec();
    ctx.out_len = v.len();
    ctx.out = unsafe { CString::from_vec_unchecked(v) };
    ctx.out.as_ptr()
}

#[no_mangle]
pub extern fn sputnikvm_out_len(ptr: *mut EvmContext) -> size_t {
    let ctx = unsafe{&mut *ptr};
    ctx.out_len
}

#[no_mangle]
pub extern fn sputnikvm_gas(ptr: *mut EvmContext) -> *const c_char {
    let ctx = unsafe{&mut *ptr};
    ctx.out = CString::new(format!("0x{:x}",ctx.vm.available_gas())).unwrap();
    ctx.out.as_ptr()
}

#[no_mangle]
pub extern fn sputnikvm_refund(ptr: *mut EvmContext) -> *const c_char {
    let ctx = unsafe{&mut *ptr};
    ctx.out = CString::new(format!("0x{:x}",ctx.vm.refunded_gas())).unwrap();
    ctx.out.as_ptr()
}

#[no_mangle]
pub extern fn sputnikvm_status(ptr: *mut EvmContext) -> i32 {
    let ctx = unsafe{&mut *ptr};
    match ctx.vm.status() {
        VMStatus::Running => SPUTNIK_VM_RUNNING,
        VMStatus::ExitedOk => SPUTNIK_VM_EXITED_OK,
        VMStatus::ExitedErr(_) => SPUTNIK_VM_EXITED_ERR,
        VMStatus::ExitedNotSupported(_) => SPUTNIK_VM_UNSUPPORTED_ERR,
    }
}

#[no_mangle]
pub extern fn sputnikvm_error(ptr: *mut EvmContext) -> *const c_char {
    let ctx = unsafe{&mut *ptr};
    match ctx.vm.status() {
        VMStatus::Running => ptr::null(),
        VMStatus::ExitedOk => ptr::null(),
        VMStatus::ExitedErr(e) => ptr::null(),//(ctx.error = CString::new(e)).as_ptr(),
        VMStatus::ExitedNotSupported(e) => ptr::null(),//(ctx.error = CString::new(e)).as_ptr(),
    }
}

#[no_mangle]
pub extern fn sputnikvm_first_account(ptr: *mut EvmContext) -> *const AccountChange {
    let ctx = unsafe{&mut *ptr};
    ctx.account =
        Accounts{
            list: ctx.vm.accounts().into_iter().map(|c|{let x: *const AccountChange = c; x}).collect(),
            index: 0,
        };
    match ctx.account.next() {
        None => ptr::null(),
        Some(x) => x
    }
}

#[no_mangle]
pub extern fn sputnikvm_next_account(ptr: *mut EvmContext) -> *const AccountChange {
    let ctx = unsafe{&mut *ptr};
    match ctx.account.next() {
        None => ptr::null(),
        Some(x) => x
    }
}

#[no_mangle]
pub extern fn sputnikvm_acc_address(q: *mut EvmContext, ptr: *const AccountChange) -> *const c_char {
    let ctx = unsafe{&mut *q};
    let acc = unsafe{&*ptr};
    let address = match acc {
        &AccountChange::Full {ref address, .. } => address,
        &AccountChange::Create {ref address, .. } => address,
        &AccountChange::IncreaseBalance (ref address, _) => address,
        &AccountChange::DecreaseBalance (ref address, _) => address,
    };
    ctx.out = CString::new(format!("0x{:x}",address)).unwrap();
    ctx.out.as_ptr()
}

#[no_mangle]
pub extern fn sputnikvm_acc_balance(q: *mut EvmContext, ptr: *const AccountChange) -> *const c_char {
    let ctx = unsafe{&mut *q};
    let acc = unsafe{&*ptr};
    let balance = match acc {
        &AccountChange::Full {ref balance, .. } => balance,
        &AccountChange::Create {ref balance, ..} => balance,
        &AccountChange::IncreaseBalance (_, ref balance) => balance,
        &AccountChange::DecreaseBalance (_, ref balance) => balance,
    };
    ctx.out = CString::new(format!("0x{:x}",balance)).unwrap();
    ctx.out.as_ptr()
}

const UPDATE_ACCOUNT : i32 = 0;
const CREATE_ACCOUNT : i32 = 1;
const SUICIDE_ACCOUNT : i32 = 2;
const ADD_BALANCE_ACCOUNT : i32 = 3;
const SUB_BALANCE_ACCOUNT : i32 = 4;

#[no_mangle]
pub extern fn sputnikvm_acc_change(ptr: *const AccountChange) -> i32 {
    let acc = unsafe{&*ptr};
    match acc {
        &AccountChange::Full {..} => UPDATE_ACCOUNT,
        &AccountChange::Create {..} => CREATE_ACCOUNT,
        &AccountChange::IncreaseBalance {..} => ADD_BALANCE_ACCOUNT,
        &AccountChange::DecreaseBalance {..} => SUB_BALANCE_ACCOUNT,
    }
}

#[no_mangle]
pub extern fn sputnikvm_acc_nonce(ptr: *const AccountChange) -> u64 {
    let acc = unsafe{&*ptr};
    match acc {
        &AccountChange::Full {nonce, ..} => nonce.into(),
        &AccountChange::Create {nonce, ..} => nonce.into(),
        _ => 0,
    }
}

#[no_mangle]
pub extern fn sputnikvm_acc_code(q: *mut EvmContext, ptr: *const AccountChange) -> *const c_char {
    let ctx = unsafe{&mut *q};
    let acc = unsafe{&*ptr};
    let bytes = match acc {
        &AccountChange::Full {ref code, ..} => Rc::clone(code),
        &AccountChange::Create {ref code, ..} => Rc::clone(code),
        _ => Rc::new(EMPTY.as_ref().into()),
    };
    ctx.out = unsafe { CString::from_vec_unchecked(bytes.to_vec()) };
    ctx.out.as_ptr()
}

#[no_mangle]
pub extern fn sputnikvm_acc_code_len(ptr: *const AccountChange) -> size_t {
    let acc = unsafe{&*ptr};
    match acc {
        &AccountChange::Full {ref code, ..} => code.len(),
        &AccountChange::Create {ref code, ..} => code.len(),
        _ => 0,
    }
}
