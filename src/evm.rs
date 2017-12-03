
use std::collections::{HashSet as Set, hash_map as map};
use std::cmp::min;
use std::rc::Rc;
use bigint::{Gas, U256, H256, Address};
use block::TransactionAction;
use sputnikvm::errors::{RequireError,CommitError};
use sputnikvm::{ValidTransaction,
                ContextVM, VM, AccountState,
                BlockhashState, Patch, HeaderParams, Memory, SeqMemory, VMStatus,
                AccountCommitment, Log, AccountChange, MachineStatus,
                MainnetFrontierPatch, MainnetHomesteadPatch, MainnetEIP150Patch, MainnetEIP160Patch};

pub enum Fork {
    Frontier,
    Homestead,
    EIP150,
    EIP160,
}

enum EVMState<M, P: Patch> {
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

pub struct EVM<M, P: Patch>(EVMState<M, P>);

impl<M: Memory + Default, P: Patch> EVM<M, P> {
    /// Create a new VM using the given transaction, block header and
    /// patch. This VM runs at the transaction level.
    pub fn new(transaction: ValidTransaction, block: HeaderParams) -> Self {
        EVM(EVMState::Constructing {
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

impl<M: Memory + Default, P: Patch> VM for EVM<M, P> {
    fn commit_account(&mut self, commitment: AccountCommitment) -> Result<(), CommitError> {
        match self.0 {
            EVMState::Running { ref mut vm, .. } => vm.commit_account(commitment),
            EVMState::Constructing { ref mut account_state, .. } => account_state.commit(commitment),
        }
    }

    fn commit_blockhash(&mut self, number: U256, hash: H256) -> Result<(), CommitError> {
        match self.0 {
            EVMState::Running { ref mut vm, .. } => vm.commit_blockhash(number, hash),
            EVMState::Constructing { ref mut blockhash_state, .. } => blockhash_state.commit(number, hash),
        }
    }

    fn status(&self) -> VMStatus {
        match self.0 {
            EVMState::Running { ref vm, finalized, .. } => {
                if !finalized {
                    VMStatus::Running
                } else {
                    vm.status()
                }
            },
            EVMState::Constructing { .. } => VMStatus::Running,
        }
    }

    fn step(&mut self) -> Result<(), RequireError> {
        let real_used_gas = self.used_gas();

        self.0 = match self.0 {
            EVMState::Constructing {
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

                EVMState::Running {
                    fresh_account_state: account_state,
                    vm,
                    intrinsic_gas: Gas::from(0u64),
                    finalized: false,
                    code_deposit: ccode_deposit,
                    preclaimed_value: cpreclaimed_value,
                }
            },
            EVMState::Running {
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
            EVMState::Running { ref vm, .. } => vm.accounts(),
            EVMState::Constructing { ref account_state, .. } => account_state.accounts(),
        }
    }

    fn used_addresses(&self) -> Set<Address> {
        match self.0 {
            EVMState::Running { ref vm, .. } => vm.used_addresses(),
            EVMState::Constructing { ref account_state, .. } => account_state.used_addresses(),
        }
    }

    fn out(&self) -> &[u8] {
        match self.0 {
            EVMState::Running { ref vm, .. } => vm.out(),
            EVMState::Constructing { .. } => &[],
        }
    }

    fn available_gas(&self) -> Gas {
        match self.0 {
            EVMState::Running { ref vm, .. } => vm.available_gas(),
            EVMState::Constructing { ref transaction, .. } => transaction.gas_limit,
        }
    }

    fn refunded_gas(&self) -> Gas {
        match self.0 {
            EVMState::Running { ref vm, .. } => vm.refunded_gas(),
            EVMState::Constructing { .. } => Gas::zero(),
        }
    }

    fn logs(&self) -> &[Log] {
        match self.0 {
            EVMState::Running { ref vm, .. } => vm.logs(),
            EVMState::Constructing { .. } => &[],
        }
    }

    fn removed(&self) -> &[Address] {
        match self.0 {
            EVMState::Running { ref vm, .. } => vm.removed(),
            EVMState::Constructing { .. } => &[],
        }
    }

    fn used_gas(&self) -> Gas {
        match self.0 {
            EVMState::Running { ref vm, intrinsic_gas, .. } => {
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
            EVMState::Constructing { .. } => Gas::zero(),
        }
    }
}

pub type GethEVM<P> = EVM<SeqMemory<P>, P>;

pub fn new_vm(
    caller: Option<Address>,
    target: Option<Address>,
    gas: Gas,
    gas_price: Gas,
    gas_limit: Gas,
    value: U256,
    input: Rc<Vec<u8>>,
    beneficiary: Option<Address>,
    timestamp: u64,
    number: U256,
    difficulty: U256,
    fork: Fork) -> Box<VM> {

    let transaction = ValidTransaction {
        caller,
        gas_price,
        gas_limit: gas,
        action: match target {
            None => TransactionAction::Create,
            Some(address) => TransactionAction::Call(address)
        },
        value,
        input,
        nonce: U256::zero(),
    };

    let block = HeaderParams {
        beneficiary: beneficiary.unwrap(),
        timestamp,
        number,
        difficulty,
        gas_limit,
    };

    match fork {
        Fork::Frontier => Box::new(GethEVM::<MainnetFrontierPatch>::new(transaction, block)),
        Fork::Homestead => Box::new(GethEVM::<MainnetHomesteadPatch>::new(transaction, block)),
        Fork::EIP150 => Box::new(GethEVM::<MainnetEIP150Patch>::new(transaction, block)),
        Fork::EIP160 => Box::new(GethEVM::<MainnetEIP160Patch>::new(transaction, block)),
    }
}
