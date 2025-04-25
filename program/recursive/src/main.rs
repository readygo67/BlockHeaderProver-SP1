//! This is a test program that takes in a sp1_core vkey and a list of inputs, and then verifies the
//! SP1 proof for each input.

#![no_main]
sp1_zkvm::entrypoint!(main);

use sha2::{Digest, Sha256};
use sp1_zkvm::lib::verify::verify_sp1_proof;
use alloy_sol_types::SolType;
use block_header_lib::PublicValuesStruct;

pub fn main() {
    let vkey1 = sp1_zkvm::io::read::<[u32; 8]>();
    let vkey2 = sp1_zkvm::io::read::<[u32; 8]>();

    let input1 = sp1_zkvm::io::read::<Vec<u8>>();
    let input2 = sp1_zkvm::io::read::<Vec<u8>>();

    println!("cycle-tracker-start: block-header-recursive");
    let pv_digest1 = Sha256::digest(input1.clone());
    verify_sp1_proof(&vkey1, &pv_digest1.into());

    let pv_digest2 = Sha256::digest(input2.clone());
    verify_sp1_proof(&vkey2, &pv_digest2.into());

    assert_eq!(input1[32..64], input2[0..32]);

    let mut begin_hash: [u8; 32] = [0; 32];
    begin_hash.copy_from_slice(&input1[0..32]);

    let mut end_hash: [u8; 32] = [0; 32];
    end_hash.copy_from_slice(&input2[32..64]);
    
    let bytes: Vec<u8> = PublicValuesStruct::abi_encode(&PublicValuesStruct {
        begin_hash: alloy_sol_types::private::FixedBytes(begin_hash),
        end_hash: alloy_sol_types::private::FixedBytes(end_hash),
    });
    println!("cycle-tracker-end: block-header-recursive");
    sp1_zkvm::io::commit_slice(&bytes);

}
