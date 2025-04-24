use sp1_sdk::{include_elf, HashableKey, Prover, ProverClient};

/// The ELF (executable and linkable format) file for the Succinct RISC-V zkVM.
pub const UNIT_ELF: &[u8] = include_elf!("block-header-unit");
pub const RECURSIVE_ELF: &[u8] = include_elf!("block-header-recursive");

fn main() {
    let prover = ProverClient::builder().cpu().build();
    let (_, vk) = prover.setup(UNIT_ELF);
    println!("unit vk digest: {}", vk.bytes32());

    let (_, vk) = prover.setup(RECURSIVE_ELF);
    println!("unit vk digest: {}", vk.bytes32());

}