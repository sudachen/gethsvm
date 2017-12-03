
extern crate sputnikvm;
extern crate bigint;
extern crate libc;
extern crate block_core;
extern crate block;

use std::mem::{drop,forget};
use std::ffi::CString;
use std::rc::Rc;
use std::ptr;
use std::slice;
use std::collections::{HashMap as Map};

use libc::{c_char,size_t};
use bigint::{U256, H256, M256, Address};
use sputnikvm::errors::{RequireError};
use sputnikvm::{VM, AccountCommitment, Log, AccountChange, VMStatus};


mod marshal;
use marshal::*;

mod evm;

const SPUTNIK_VM_FORK_FRONTIER : i32 = 0;
const SPUTNIK_VM_FORK_HOMESTEAD : i32 = 1;
const SPUTNIK_VM_FORK_GASREPRICE : i32 = 2;
const SPUTNIK_VM_FORK_DIEHARD : i32 = 3;
const SPUTNIK_VM_EXITED_OK : i32 = 0;
const SPUTNIK_VM_EXITED_ERR : i32 = 1;
const SPUTNIK_VM_RUNNING : i32 = 2;
const SPUTNIK_VM_UNSUPPORTED_ERR : i32 = 3;
const SPUTNIK_VM_REQUIRE_ACCOUNT : i32 = 2;
const SPUTNIK_VM_REQUIRE_CODE : i32 = 3;
const SPUTNIK_VM_REQUIRE_HASH : i32 = 4;
const SPUTNIK_VM_REQUIRE_VALUE : i32 = 5;
const UPDATE_ACCOUNT : i32 = 0;
const CREATE_ACCOUNT : i32 = 1;
//const SUICIDE_ACCOUNT : i32 = 2;
const ADD_BALANCE_ACCOUNT : i32 = 3;
const SUB_BALANCE_ACCOUNT : i32 = 4;

struct Accounts {
    list : Vec<*const AccountChange>,
    index: usize
}

impl Accounts {
    fn next(&mut self) -> Option<*const AccountChange> {
        if self.index < self.list.len() {
            let i = self.index;
            self.index+=1;
            Some(self.list[i])
        } else {None}
    }
}

struct KV {
    list : Vec<(H256,H256)>,
    index: usize
}

impl KV {
    fn next(&mut self) -> Option<&(H256,H256)> {
        if self.index < self.list.len() {
            let i = self.index;
            self.index+=1;
            Some(&self.list[i])
        } else {None}
    }
}

pub struct EvmContext {
    vm : Box<VM>,
    blocknum : u64,
    address : Address,
    hash : H256,
    error : CString,
    account : Accounts,
    kv: KV,
}

#[no_mangle]
pub extern fn sputnikvm_is_implemented() -> i32 {
    1
}

#[no_mangle]
pub extern fn sputnikvm_context(
    gas: Ptr,
    price: Ptr,
    value: Ptr,
    caller: Ptr,
    target: Ptr,
    bytes: Ptr,
    bytes_len: usize,
    gas_limit: Ptr,
    coinbase: Ptr,
    fork: i32,
    blocknum: u64,
    time: u64,
    difficulty: Ptr) -> *mut EvmContext {

    let vm_impl = evm::new_vm(
        caller.into(),
        target.into(),
        gas.into(),
        price.into(),
        gas_limit.into(),
        value.into(),
        rcv_from_bits(bytes, bytes_len),
        coinbase.into(),
        time,
        blocknum.into(),
        difficulty.into(),
        match fork {
            SPUTNIK_VM_FORK_FRONTIER => evm::Fork::Frontier,
            SPUTNIK_VM_FORK_HOMESTEAD => evm::Fork::Homestead,
            SPUTNIK_VM_FORK_GASREPRICE => evm::Fork::EIP150,
            SPUTNIK_VM_FORK_DIEHARD => evm::Fork::EIP160,
            _ => panic!() // TODO gracefull way to handle this error
        });

    let mut ctx = Box::new(EvmContext {
        vm : vm_impl,
        blocknum : 0,
        address : Address::new(),
        hash : 0.into(),
        error : CString::new("").unwrap(),
        account: Accounts{list: Vec::new(), index: 0},
        kv: KV{list: Vec::new(), index: 0},
    });

    let ptr: *mut _ = &mut *ctx;
    forget(ctx);
    ptr
}

#[no_mangle]
pub extern fn sputnikvm_terminate(ptr: *mut EvmContext) {
    drop(ptr)
}

#[no_mangle]
pub extern fn sputnikvm_fire(ptr: *mut EvmContext) -> i32 {
    let ctx = unsafe{&mut *ptr};
    match ctx.vm.fire() {
        Err(RequireError::Account(address)) => {
            ctx.address = address;
            SPUTNIK_VM_REQUIRE_ACCOUNT
        },
        Err(RequireError::AccountCode(address)) => {
            ctx.address = address;
            SPUTNIK_VM_REQUIRE_CODE
        },
        Err(RequireError::AccountStorage(address, index)) => {
            ctx.address = address;
            ctx.hash = index.into();
            SPUTNIK_VM_REQUIRE_VALUE
        },
        Err(RequireError::Blockhash(number)) => {
            ctx.blocknum = number.as_u64();
            SPUTNIK_VM_REQUIRE_HASH
        },
        Ok(()) => SPUTNIK_VM_EXITED_OK,
    }
}

#[no_mangle]
pub extern fn sputnikvm_req_address_copy(ptr: *mut EvmContext, out: *mut u8) -> size_t {
    let ctx = unsafe{&*ptr};
    unsafe { ptr::copy(&ctx.address[0], out, 20) };
    20
}

#[no_mangle]
pub extern fn sputnikvm_req_hash_copy(ptr: *mut EvmContext, out: *mut u8) -> size_t {
    let ctx = unsafe{&*ptr};
    unsafe { ptr::copy(&ctx.hash[0], out, 32) };
    32
}

#[no_mangle]
pub extern fn sputnikvm_req_blocknum(ptr: *mut EvmContext) -> u64 {
    let ctx = unsafe{&*ptr};
    ctx.blocknum
}

static EMPTY: [u8; 0] = [];

#[no_mangle]
pub extern fn sputnikvm_commit_account(
    ptr: *mut EvmContext,
    addr: Ptr,
    nonce: u64,
    balance: Ptr,
    code: Ptr,
    code_len: usize) {

    let ctx = unsafe{&mut *ptr};

    match balance.raw() {
        None => ctx.vm.commit_account(AccountCommitment::Nonexist(addr.into())),
        _ => ctx.vm.commit_account(AccountCommitment::Full {
            address: addr.into(),
            balance: balance.into(),
            code: rcv_from_bits(code, code_len),
            nonce: nonce.into(),
        })
    }.expect("failed on commit account");
}

#[no_mangle]
pub extern fn sputnikvm_commit_code(
    ptr: *mut EvmContext,
    addr: Ptr,
    code: Ptr,
    code_len: usize) {

    let ctx = unsafe{&mut *ptr};

    ctx.vm.commit_account(AccountCommitment::Code {
        address: addr.into(),
        code: rcv_from_bits(code, code_len),
    }).expect("failed on commit code");
}

#[no_mangle]
pub extern fn sputnikvm_commit_blockhash(
    ptr: *mut EvmContext,
    number: u64,
    hash: Ptr) {

    let ctx = unsafe{&mut *ptr};
    ctx.vm.commit_blockhash(number.into(), hash.into()).expect("failed on commit blackhash");
}

#[no_mangle]
pub extern fn sputnikvm_commit_value(
    ptr: *mut EvmContext,
    addr: *const u8,
    key: *const u8,
    value: *const u8) {

    let ctx = unsafe{&mut *ptr};
    ctx.vm.commit_account(AccountCommitment::Storage {
        address: address_from_bits(addr),
        index: h256_from_bits(key).into(),
        value: h256_from_bits(value).into(),
    }).expect("failed on commit value");
}

#[no_mangle]
pub extern fn sputnikvm_out_len(ptr: *mut EvmContext) -> size_t {
    let ctx = unsafe{&mut *ptr};
    ctx.vm.out().len()
}

#[no_mangle]
pub extern fn sputnikvm_out_copy(ptr: *mut EvmContext, out: *mut u8) -> size_t {
    let ctx = unsafe{&mut *ptr};
    let v = ctx.vm.out();
    let len = v.len();
    unsafe { ptr::copy(&v[0],out, len) };
    len
}

#[no_mangle]
pub extern fn sputnikvm_gas_copy(ptr: *mut EvmContext, bits: *mut u8) -> size_t {
    let ctx = unsafe{&mut *ptr};
    let out = unsafe { slice::from_raw_parts_mut( bits, 32) };
    let gas = ctx.vm.available_gas();
    let u256 : U256 = gas.into();
    u256.to_little_endian(out);
    32
}

#[no_mangle]
pub extern fn sputnikvm_refund_copy(ptr: *mut EvmContext, bits: *mut u8) -> size_t {
    let ctx = unsafe{&mut *ptr};
    let out = unsafe { slice::from_raw_parts_mut( bits, 32) };
    let gas = ctx.vm.refunded_gas();
    let u256 : U256 = gas.into();
    u256.to_little_endian(out);
    32
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
        //VMStatus::ExitedErr(e) =>
        //VMStatus::ExitedNotSupported(e) =>
        _ => {
            ctx.error = CString::new("error occured").unwrap(); ctx.error.as_ptr()
        },
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
pub extern fn sputnikvm_first_account(ptr: *mut EvmContext) -> *const AccountChange {
    let ctx = unsafe{&mut *ptr};
    ctx.account =
        Accounts{
            list: ctx.vm.accounts().into_iter().map(|c|{let x: *const AccountChange = c; x}).collect(),
            index: 0,
        };
    sputnikvm_next_account(ptr)
}

#[no_mangle]
pub extern fn sputnikvm_acc_address_copy(ptr: *const AccountChange, out: *mut u8) -> size_t {
    let acc = unsafe{&*ptr};
    let address = match acc {
        &AccountChange::Full {ref address, .. } => address,
        &AccountChange::Create {ref address, .. } => address,
        &AccountChange::IncreaseBalance (ref address, _) => address,
        &AccountChange::DecreaseBalance (ref address, _) => address,
    };
    unsafe { ptr::copy(&address[0],out,20) };
    20
}

#[no_mangle]
pub extern fn sputnikvm_acc_balance_copy(ptr: *const AccountChange, bits: *mut u8) -> size_t {
    let acc = unsafe{&*ptr};
    let balance : U256 = *match acc {
        &AccountChange::Full {ref balance, .. } => balance,
        &AccountChange::Create {ref balance, ..} => balance,
        &AccountChange::IncreaseBalance (_, ref balance) => balance,
        &AccountChange::DecreaseBalance (_, ref balance) => balance,
    };
    let out = unsafe { slice::from_raw_parts_mut( bits, 32) };
    balance.to_little_endian(out);
    32
}

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
pub extern fn sputnikvm_acc_code_len(ptr: *const AccountChange) -> size_t {
    let acc = unsafe{&*ptr};
    match acc {
        &AccountChange::Full {ref code, ..} => code.len(),
        &AccountChange::Create {ref code, ..} => code.len(),
        _ => 0,
    }
}

#[no_mangle]
pub extern fn sputnikvm_acc_code_copy(ptr: *const AccountChange, out: *mut u8) -> size_t {
    let acc = unsafe{&*ptr};
    let bytes = match acc {
        &AccountChange::Full {ref code, ..} => Rc::clone(code),
        &AccountChange::Create {ref code, ..} => Rc::clone(code),
        _ => Rc::new(EMPTY.as_ref().into()),
    };
    let len = bytes.len();
    unsafe { ptr::copy(&bytes[0], out,len) };
    len
}

#[no_mangle]
pub extern fn sputnikvm_acc_next_kv_copy(q: *mut EvmContext, k: *mut u8, v: *mut u8) -> size_t {
    let ctx = unsafe{&mut *q};
    match ctx.kv.next() {
        None => 0,
        Some(&(x,y)) => {
            unsafe { ptr::copy(&x[0],k, 32) };
            unsafe { ptr::copy(&y[0],v, 32) };
            32*2
        }
    }
}

fn collect_values(m : Map<U256,M256> ) -> Vec<(H256,H256)> {
    m.iter().map(|(k, v)| { (H256::from(k), H256::from(*v)) }).collect()
}

#[no_mangle]
pub extern fn sputnikvm_acc_first_kv_copy(q: *mut EvmContext, ptr: *const AccountChange, k: *mut u8, v: *mut u8) -> size_t {
    let acc = unsafe{&*ptr};
    let ctx = unsafe{&mut *q};
    ctx.kv =
        KV {
            list: match acc {
                &AccountChange::Full { ref changing_storage, .. } => collect_values(changing_storage.clone().into()),
                &AccountChange::Create { ref storage, .. } => collect_values(storage.clone().into()),
                _ => Vec::new(),
            },
            index: 0,
        };
    sputnikvm_acc_next_kv_copy(q,k,v)
}

#[no_mangle]
pub extern fn sputnikvm_logs_count(ptr: *mut EvmContext) -> size_t {
    let ctx = unsafe{&mut *ptr};
    ctx.vm.logs().len()
}

#[no_mangle]
pub extern fn sputnikvm_log(ptr: *mut EvmContext, index: size_t) -> *const Log {
    let ctx = unsafe{&mut *ptr};
    let logs : &[Log]= ctx.vm.logs();
    let len = logs.len();
    if index < len { let x : *const Log = &logs[index]; x } else { ptr::null() }
}

#[no_mangle]
pub extern fn sputnikvm_log_address_copy(ptr: *const Log, address: *mut u8) -> size_t {
    let log : &Log = unsafe{&*ptr};
    unsafe { ptr::copy(&log.address[0],address,20) };
    20
}

#[no_mangle]
pub extern fn sputnikvm_log_data_len(ptr: *const Log) -> size_t {
    let log : &Log = unsafe{&*ptr};
    log.data.len()
}

#[no_mangle]
pub extern fn sputnikvm_log_data_copy(ptr: *const Log, data: *mut u8) -> size_t {
    let log : &Log = unsafe{&*ptr};
    let len = log.data.len();
    unsafe { ptr::copy(&log.data[0],data,len) };
    len
}

#[no_mangle]
pub extern fn sputnikvm_log_topics_count(ptr: *const Log) -> size_t {
    let log : &Log = unsafe{&*ptr};
    log.topics.len()
}

#[no_mangle]
pub extern fn sputnikvm_log_topic_copy(ptr: *const Log, index: size_t, topic: *mut u8) -> size_t {
    let log : &Log = unsafe{&*ptr};
    if index < log.topics.len() {
        unsafe { ptr::copy(&log.topics[index][0], topic, 32) };
        32
    } else {
        0
    }
}

#[no_mangle]
pub extern fn sputnikvm_suicides_count(ptr: *mut EvmContext) -> size_t {
    let ctx = unsafe{&mut *ptr};
    ctx.vm.removed().len()
}

#[no_mangle]
pub extern fn sputnikvm_suicide_copy(ptr: *mut EvmContext, index: size_t, address: *mut u8) -> size_t {
    let ctx = unsafe{&mut *ptr};
    let suicides : &[Address] = ctx.vm.removed();
    if index < suicides.len() {
        unsafe { ptr::copy(&suicides[index][0],address,20) };
        20
    } else {
        0
    }
}
