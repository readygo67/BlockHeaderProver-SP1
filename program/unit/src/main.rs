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
    // Read an input to the program.
    //
    // Behind the scenes, this compiles down to a custom system call which handles reading inputs
    // from the prover.
    let header = sp1_zkvm::io::read::<String>();
    //let header :&str="01000000b5fbf970bf362cc3203d71022d0764ce966a9d5cee7615354e273624000000008c209cca50575be7aad6faf11c26af9d91fc91f9bf953c1e7d4fca44e44be3fa3d286f49ffff001d2e18e5ed";
    let header_bytes = hex::decode(header).unwrap();

    //TODO, retrieve the header_bytes[4:36] as begin hash
    let mut begin_hash: [u8; 32] = [0; 32];
    begin_hash.copy_from_slice(&header_bytes[4..36]);

    println!("cycle-tracker-start: double_sha256");
    let end_hash = double_sha256(header_bytes.as_slice());
    println!(
        "begin_hash: {:?}, end_hash: {:?} ",
        hex::encode(begin_hash),
        hex::encode(end_hash)
    );
    println!("cycle-tracker-end: double_sha256");

    // Encode the public values of the program.
    let bytes: Vec<u8> = PublicValuesStruct::abi_encode(&PublicValuesStruct {
        begin_hash: alloy_sol_types::private::FixedBytes(begin_hash),
        end_hash: alloy_sol_types::private::FixedBytes(end_hash),
    });

    // Commit to the public values of the program. The final proof will have a commitment to all the
    // bytes that were committed to.
    sp1_zkvm::io::commit_slice(&bytes);
}

