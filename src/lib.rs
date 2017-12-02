
extern crate sputnikvm;
extern crate bigint;
extern crate libc;
extern crate block_core;
extern crate block;

use std::mem::{drop,forget};
use std::ffi::{CStr,CString};
use std::rc::Rc;
use std::ptr;
use std::slice;
use std::str::FromStr;
use std::collections::{HashMap as Map, HashSet as Set, hash_map as map};
use std::cmp::min;
use std::ops::Deref;

use libc::{c_char,size_t};
use bigint::{Gas, H160, U256, H256, M256, Address};
use block::TransactionAction;
use sputnikvm::errors::{RequireError,CommitError};
use sputnikvm::{ValidTransaction, Storage,
                State, Machine, Context, ContextVM, VM, AccountState,
                BlockhashState, Patch, HeaderParams, Memory, SeqMemory, VMStatus,
                AccountCommitment, Log, AccountChange, MachineStatus};
use sputnikvm::{MainnetFrontierPatch, MainnetHomesteadPatch, MainnetEIP160Patch};

enum VM1State<M, P: Patch> {
    Running {
        vm: ContextVM<M, P>,
        intrinsic_gas: Gas,
        preclaimed_value: U256,
        finalized: bool,
        code_deposit: bool,
        fresh_account_state: AccountState<P::Account>,
    },
    Constructing {
        transaction: ValidTransaction,
        block: HeaderParams,
        account_state: AccountState<P::Account>,
        blockhash_state: BlockhashState,
    },
}

pub struct VM1<M, P: Patch>(VM1State<M, P>);

impl<M: Memory + Default, P: Patch> VM1<M, P> {
    /// Create a new VM using the given transaction, block header and
    /// patch. This VM runs at the transaction level.
    pub fn new(transaction: ValidTransaction, block: HeaderParams) -> Self {
        VM1(VM1State::Constructing {
            transaction: transaction,
            block: block,
            account_state: AccountState::default(),
            blockhash_state: BlockhashState::default(),
        })
    }
}

/// Finalize a transaction. This should not be used when invoked
/// by an opcode.
fn finalize_transaction<M: Memory + Default, P: Patch>(
    vm: &mut ContextVM<M,P>,
    real_used_gas: Gas,
    preclaimed_value: U256,
    fresh_account_state: &AccountState<P::Account>) -> Result<(), RequireError> {

    let status = vm.machines[0].status.clone();
    let st = &mut vm.machines[0].state;

    st.account_state.require(st.context.address)?;

    match status {
        MachineStatus::ExitedOk => {
            // Requires removed accounts to exist.
            for address in &st.removed {
                st.account_state.require(*address)?;
            }
        },
        MachineStatus::ExitedErr(_) => {
            // If exited with error, reset all changes.
            st.account_state = fresh_account_state.clone();
            // on error all gas is consumed
            // m.state.account_state.increase_balance(m.state.context.caller, preclaimed_value);
            st.logs = Vec::new();
            st.removed = Vec::new();
        },
        _ => panic!(),
    }

    let gas_dec = (st.memory_gas() + st.used_gas) * st.context.gas_price;
    st.account_state.increase_balance(st.context.caller, preclaimed_value);
    st.account_state.decrease_balance(st.context.caller, gas_dec.into());

    for address in &st.removed {
        st.account_state.remove(*address).unwrap();
    }

    match status {
        MachineStatus::ExitedOk => Ok(()),
        MachineStatus::ExitedErr(_) => Ok(()),
        _ => panic!(),
    }
}

impl<M: Memory + Default, P: Patch> VM for VM1<M, P> {
    fn commit_account(&mut self, commitment: AccountCommitment) -> Result<(), CommitError> {
        match self.0 {
            VM1State::Running { ref mut vm, .. } => vm.commit_account(commitment),
            VM1State::Constructing { ref mut account_state, .. } => account_state.commit(commitment),
        }
    }

    fn commit_blockhash(&mut self, number: U256, hash: H256) -> Result<(), CommitError> {
        match self.0 {
            VM1State::Running { ref mut vm, .. } => vm.commit_blockhash(number, hash),
            VM1State::Constructing { ref mut blockhash_state, .. } => blockhash_state.commit(number, hash),
        }
    }

    fn status(&self) -> VMStatus {
        match self.0 {
            VM1State::Running { ref vm, finalized, .. } => {
                if !finalized {
                    VMStatus::Running
                } else {
                    vm.status()
                }
            },
            VM1State::Constructing { .. } => VMStatus::Running,
        }
    }

    fn step(&mut self) -> Result<(), RequireError> {
        let real_used_gas = self.used_gas();

        self.0 = match self.0 {
            VM1State::Constructing {
                ref transaction, ref block,
                ref mut account_state, ref blockhash_state
            } => {
                let address = transaction.address();
                account_state.require(address)?;

                let ccode_deposit = match transaction.action {
                    TransactionAction::Call(_) => false,
                    TransactionAction::Create => true,
                };

                let cpreclaimed_value = transaction.preclaimed_value();
                let ccontext = transaction.clone().into_context::<P>(Gas::from(0u64), None, account_state, false)?;
                let cblock = block.clone();
                let caccount_state = account_state.clone();
                let cblockhash_state = blockhash_state.clone();
                let account_state = caccount_state;
                let mut vm = ContextVM::with_states(ccontext, cblock,
                                                    account_state.clone(),
                                                    cblockhash_state);

                if ccode_deposit {
                    vm.machines[0].initialize_create(cpreclaimed_value).unwrap();
                } else {
                    vm.machines[0].initialize_call(cpreclaimed_value);
                }

                VM1State::Running {
                    fresh_account_state: account_state,
                    vm,
                    intrinsic_gas: Gas::from(0u64),
                    finalized: false,
                    code_deposit: ccode_deposit,
                    preclaimed_value: cpreclaimed_value,
                }
            },
            VM1State::Running {
                ref mut vm,
                ref mut finalized,
                ref mut code_deposit,
                ref fresh_account_state,
                preclaimed_value,
                ..
            } => return match vm.status() {
                VMStatus::Running => {
                    vm.step()
                },
                VMStatus::ExitedNotSupported(_) => {
                    Ok(())
                },
                _ => {
                    if *code_deposit {
                        vm.machines[0].code_deposit();
                        *code_deposit = false;
                        return Ok(());
                    } else if !*finalized {
                        vm.machines[0].finalize(vm.runtime.block.beneficiary,
                                                real_used_gas, preclaimed_value,
                                                fresh_account_state)?;
                        //finalize_transaction(vm,real_used_gas,preclaimed_value,fresh_account_state)?;
                        *finalized = true;
                        Ok(())
                    } else {
                        vm.step()
                    }
                }
            }
        };
        Ok(())
    }

    fn accounts(&self) -> map::Values<Address, AccountChange> {
        match self.0 {
            VM1State::Running { ref vm, .. } => vm.accounts(),
            VM1State::Constructing { ref account_state, .. } => account_state.accounts(),
        }
    }

    fn used_addresses(&self) -> Set<Address> {
        match self.0 {
            VM1State::Running { ref vm, .. } => vm.used_addresses(),
            VM1State::Constructing { ref account_state, .. } => account_state.used_addresses(),
        }
    }

    fn out(&self) -> &[u8] {
        match self.0 {
            VM1State::Running { ref vm, .. } => vm.out(),
            VM1State::Constructing { .. } => &[],
        }
    }

    fn available_gas(&self) -> Gas {
        match self.0 {
            VM1State::Running { ref vm, .. } => vm.available_gas(),
            VM1State::Constructing { ref transaction, .. } => transaction.gas_limit,
        }
    }

    fn refunded_gas(&self) -> Gas {
        match self.0 {
            VM1State::Running { ref vm, .. } => vm.refunded_gas(),
            VM1State::Constructing { .. } => Gas::zero(),
        }
    }

    fn logs(&self) -> &[Log] {
        match self.0 {
            VM1State::Running { ref vm, .. } => vm.logs(),
            VM1State::Constructing { .. } => &[],
        }
    }

    fn removed(&self) -> &[Address] {
        match self.0 {
            VM1State::Running { ref vm, .. } => vm.removed(),
            VM1State::Constructing { .. } => &[],
        }
    }

    fn used_gas(&self) -> Gas {
        match self.0 {
            VM1State::Running { ref vm, intrinsic_gas, .. } => {
                match vm.machines[0].status() {
                    MachineStatus::ExitedErr(_) =>
                        vm.machines[0].state().context.gas_limit + intrinsic_gas,
                    MachineStatus::ExitedOk => {
                        let total_used = vm.machines[0].state().memory_gas() + vm.machines[0].state().used_gas + intrinsic_gas;
                        let refund_cap = total_used / Gas::from(2u64);
                        let refunded = min(refund_cap, vm.machines[0].state().refunded_gas);
                        total_used - refunded
                    }
                    _ => Gas::zero(),
                }
            }
            VM1State::Constructing { .. } => Gas::zero(),
        }
    }
}

pub type SeqVM1<P> = VM1<SeqMemory<P>, P>;

#[no_mangle]
pub extern fn sputnikvm_is_implemented() -> i32 {
  1
}

fn address_from_bits( ptr: *const u8 ) -> Address {
    let bits = unsafe { slice::from_raw_parts( ptr, 20) };
    Address::from(bits)
}

use std::io::Write;

fn u256_from_bits( ptr: *const u8 ) -> U256 {
    let bytes = unsafe { slice::from_raw_parts( ptr, 32) };
    let mut ret = [0u64; 4];
    for i in 0..bytes.len() {
        let pos = i / 8;
        ret[pos] += (bytes[i] as u64) << ((i % 8) * 8);
    }
    writeln!(std::io::stderr(),"U256={:x},{}",U256(ret),U256(ret));
    U256(ret)
}

fn gas_from_bits( ptr: *const u8 ) -> Gas {
    u256_from_bits(ptr).into()
}

fn h256_from_bits( ptr: *const u8 ) -> H256 {
    let mut ret = [0u8; 32];
    unsafe{ ptr::copy(ptr,&mut ret[0],32) }
    writeln!(std::io::stderr(),"H256={:x},{}",H256(ret),H256(ret));
    H256(ret)
}

fn m256_from_bits( ptr: *const u8 ) -> M256 {
    u256_from_bits(ptr).into()
}

fn vec_from_bits( ptr: *const u8, len: usize ) -> Vec<u8> {
    let mut v : Vec<u8> = Vec::with_capacity(len);
    if len > 0 {
        unsafe {
            v.set_len(len);
            ptr::copy(ptr,&mut v[0],len);
        }
    }
    v
}

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
    out : CString,
    account : Accounts,
    kv: KV,
}

const SPUTNIK_VM_FORK_FRONTIER : i32 = 0;
const SPUTNIK_VM_FORK_HOMESTEAD : i32 = 1;
const SPUTNIK_VM_FORK_GASREPRICE : i32 = 2;
const SPUTNIK_VM_FORK_DIEHARD : i32 = 3;
const G_TXDATAZERO: u64 = 4;
const G_TXDATANONZERO: u64 = 68;
const G_TRANSACTION: u64 = 21000;

#[no_mangle]
pub extern fn sputnikvm_context(
    create_new: i32,
    gas: *const u8,
    price: *const u8,
    value: *const u8,
    caller: *const u8,
    target: *const u8,
    bytes: *const u8,
    bytes_len: usize,
    gas_limit: *const u8,
    coinbase: *const u8,
    fork: i32,
    blocknum: u64,
    time: u64,
    difficulty: *const u8) -> *mut EvmContext {

    fn new_vm( t: ValidTransaction, p: HeaderParams, fork: i32 ) -> Box<VM> {
        match fork {
            SPUTNIK_VM_FORK_FRONTIER => Box::new(SeqVM1::<MainnetFrontierPatch>::new(t, p)),
            SPUTNIK_VM_FORK_HOMESTEAD => Box::new(SeqVM1::<MainnetHomesteadPatch>::new(t, p)),
            SPUTNIK_VM_FORK_DIEHARD => Box::new(SeqVM1::<MainnetEIP160Patch>::new(t, p)),
            _ => Box::new(SeqVM1::<MainnetEIP160Patch>::new(t, p)),
        }
    };

    let vm_impl = new_vm(
        ValidTransaction {
            caller: Some(address_from_bits(caller)),
            gas_price: gas_from_bits(price),
            gas_limit: gas_from_bits(gas),
            action: if create_new != 0 { TransactionAction::Create } else { TransactionAction::Call(address_from_bits(target)) },
            value: u256_from_bits(value),
            input: Rc::new(vec_from_bits(bytes, bytes_len)),
            nonce: U256::zero(),
        },
        HeaderParams {
            beneficiary: address_from_bits(coinbase),
            timestamp: time,
            number: blocknum.into(),
            difficulty: u256_from_bits(difficulty),
            gas_limit: gas_from_bits(gas_limit),
        },
        fork,
    );

    let mut ctx = Box::new(EvmContext {
        vm : vm_impl,
        blocknum : 0,
        address : Address::new(),
        hash : 0.into(),
        out : CString::new("").unwrap(),
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
    addr: *const u8,
    nonce: u64,
    balance: *const u8,
    code: *const u8,
    code_len: usize) {

    let ctx = unsafe{&mut *ptr};

    if balance.is_null() {
        ctx.vm.commit_account(AccountCommitment::Full {
            address: address_from_bits(addr),
            balance: U256::zero(),
            code: Rc::new(EMPTY.as_ref().into()),
            nonce: U256::zero(),
        });
    } else {
        ctx.vm.commit_account(AccountCommitment::Full {
            address: address_from_bits(addr),
            balance: u256_from_bits(balance),
            code: Rc::new(if code.is_null() {
                EMPTY.as_ref().into()
            } else {
                vec_from_bits(code, code_len)
            }),
            nonce: nonce.into(),
        });
    }
}

#[no_mangle]
pub extern fn sputnikvm_commit_code(
    ptr: *mut EvmContext,
    addr: *const u8,
    code: *const u8,
    code_len: usize) {

    let ctx = unsafe{&mut *ptr};

    ctx.vm.commit_account(AccountCommitment::Code {
        address: address_from_bits(addr),
        code: Rc::new(if code.is_null() {
            EMPTY.as_ref().into()
        } else {
            vec_from_bits(code, code_len)
        }),
    });
}

#[no_mangle]
pub extern fn sputnikvm_commit_blockhash(
    ptr: *mut EvmContext,
    number: u64,
    hash: *const u8) {

    let ctx = unsafe{&mut *ptr};
    ctx.vm.commit_blockhash(number.into(), h256_from_bits(hash));
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
    });
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
        VMStatus::ExitedErr(e) => ptr::null(),//(ctx.error = CString::new(e)).as_ptr(),
        VMStatus::ExitedNotSupported(e) => ptr::null(),//(ctx.error = CString::new(e)).as_ptr(),
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
