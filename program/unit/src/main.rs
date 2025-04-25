//! A simple program that takes a number `n` as input, and writes the `n-1`th and `n`th fibonacci
//! number as an output.

// These two lines are necessary for the program to properly compile.
//
// Under the hood, we wrap your main function with some extra code so that it behaves properly
// inside the zkVM.
#![no_main]
sp1_zkvm::entrypoint!(main);

use alloy_sol_types::SolType;
use block_header_lib::{double_sha256, PublicValuesStruct};

pub fn main() {
    let header = sp1_zkvm::io::read::<String>();
    let header_bytes = hex::decode(header).unwrap();
    println!("cycle-tracker-start: block-header-unit");
    let mut begin_hash: [u8; 32] = [0; 32];
    begin_hash.copy_from_slice(&header_bytes[4..36]);


    let end_hash = double_sha256(header_bytes.as_slice());
  

    // Encode the public values of the program.
    let bytes: Vec<u8> = PublicValuesStruct::abi_encode(&PublicValuesStruct {
        begin_hash: alloy_sol_types::private::FixedBytes(begin_hash),
        end_hash: alloy_sol_types::private::FixedBytes(end_hash),
    });
    println!("cycle-tracker-end: block-header-unit");

    sp1_zkvm::io::commit_slice(&bytes);
}

