//! An end-to-end example of using the SP1 SDK to generate a proof of a program that can be executed
//! or have a core proof generated.
//!
//! You can run this script using the following command:
//! ```shell
//! RUST_LOG=info cargo run --release -- --execute
//! ```
//! or
//! ```shell
//! RUST_LOG=info cargo run --release -- --prove
//! ```

use alloy_sol_types::SolType;
use clap::Parser;
use block_header_lib::{double_sha256, PublicValuesStruct};
use hex;
use sp1_sdk::{include_elf, ProverClient, SP1Stdin};
use std::borrow::Borrow;
use sp1_prover::{CoreSC, Groth16Bn254Proof, HashableKey, InnerSC, PlonkBn254Proof, SP1Prover,SP1ProvingKey, SP1VerifyingKey, components::SP1ProverComponents};
use sp1_prover::components::CpuProverComponents;
use sp1_stark::{
    baby_bear_poseidon2::BabyBearPoseidon2,
    shape::{OrderedShape, Shape},
    Challenge, MachineProver, MachineProvingKey, SP1ProverOpts, ShardProof, SplitOpts,
    StarkGenericConfig, StarkVerifyingKey, Val, Word, DIGEST_SIZE,
};
use sp1_recursion_core::air::RecursionPublicValues;
use p3_field::PrimeField32;
use sp1_core_machine::utils::setup_logger;

/// The ELF (executable and linkable format) file for the Succinct RISC-V zkVM.
pub const UNIT_ELF: &[u8] = include_elf!("block-header-unit");
pub const RECURSIVE_ELF: &[u8] = include_elf!("block-header-recursive");

/// The arguments for the command.
// #[derive(Parser, Debug)]
// #[command(author, version, about, long_about = None)]
// struct Args {
//     #[arg(long)]
//     execute: bool,

//     #[arg(long)]
//     prove: bool,

//     #[arg(long)]
//     unit : bool,

//     #[arg(long)]
//     recursive : bool,

//     #[arg(long, default_value = "1")]
//     n: u32,

//     #[arg(long, default_value = "0000000")]
//     header: String,
// }

fn main() {
    setup_logger();
    let unit_elf = UNIT_ELF;

    // Test program which verifies proofs of a vkey and a list of committed inputs.
    let recursive_elf = RECURSIVE_ELF;

    tracing::info!("initializing prover");
    let prover = SP1Prover::<CpuProverComponents>::new();

    tracing::info!("setup unit elf");
    let (_, unit_pk_d, unit_program, unit_vk) = prover.setup(unit_elf);

    tracing::info!("setup recursive elf");
    let (_, recursive_pk_d, recursive_program, recursive_vk) = prover.setup(recursive_elf);

    
    let opts = SP1ProverOpts::auto();

    tracing::info!("prove headers");
    let headers :[String;3] = [
        String::from("01000000b5fbf970bf362cc3203d71022d0764ce966a9d5cee7615354e273624000000008c209cca50575be7aad6faf11c26af9d91fc91f9bf953c1e7d4fca44e44be3fa3d286f49ffff001d2e18e5ed"),
        String::from("010000003c668f799ca5472fd05b8d43c574469fbec46ae3ffec010cdf6ee31100000000a97c6e691b813753248aa4614e4d3a34a3d1471e6ad863a392ccf4687d857a30f92b6f49ffff001d22239e3b"),
        String::from("010000001588b0752fb18960bf8b1728964d091b638e35e3a2c9ed32991da8c300000000cf18302909e57a7687e38d109ff19d01e85fd0f5517ffe821055765193ca51da162f6f49ffff001d16a2ddc4"),
    ];

    let mut compressed_unit_proofs = Vec::new(); // 创建一个 Vec 来存放所有的 proof
    let mut unit_public_values = Vec::new();
    for i in 0..headers.len() {
        let mut stdin = SP1Stdin::new();
        // let data = hex::decode(headers[i].clone()).unwrap();
        stdin.write(&headers[i].clone());
        tracing::info!("build {}th unit proof", i);

        let proof =  prover.prove_core(
            &unit_pk_d,
            unit_program.clone(),
            &stdin,
            opts,
            Default::default(),
        ).unwrap();

        let public_value = proof.public_values.to_vec().clone();
        // println!("{} public values {:#?}", i,  hex::encode(public_value.clone()));
        tracing::info!("compress {}th unit proof", i);
        let compressed_proof = prover.compress(&unit_vk, proof, vec![], opts).unwrap();
        prover.verify_compressed(&compressed_proof, &unit_vk).unwrap();
        // println!("{} compresed proof verify success", i);
        
        compressed_unit_proofs.push(compressed_proof.clone());
        unit_public_values.push(public_value.clone());
        tracing::info!("verify {}th compressed unit proof success", i);

    }

 /* 
    // Run verify program with keccak vkey, subproofs, and their committed values.
    let mut stdin = SP1Stdin::new();
    let vkey_digest = unit_vk.hash_babybear();
    let vkey_digest: [u32; 8] = vkey_digest
        .iter()
        .map(|n| n.as_canonical_u32())
        .collect::<Vec<_>>()
        .try_into()
        .unwrap();
    stdin.write(&vkey_digest);
    stdin.write(&vec![unit_public_values[0].clone(), unit_public_values[1].clone(), unit_public_values[2].clone()]);
    stdin.write_proof(compressed_unit_proofs[0].clone(), unit_vk.vk.clone());
    stdin.write_proof(compressed_unit_proofs[1].clone(), unit_vk.vk.clone());
    stdin.write_proof(compressed_unit_proofs[2].clone(), unit_vk.vk.clone());


    tracing::info!("build recursive proof (core)");
    let recursive_proof =
        prover.prove_core(&recursive_pk_d, recursive_program, &stdin, opts, Default::default()).unwrap();
    // let public_values = verify_proof.public_values.clone();

    tracing::info!("compress recursive proof");
    let compressed_recursive_proof = prover.compress(
        &recursive_vk,
        recursive_proof,
        vec![compressed_unit_proofs[0].clone(), compressed_unit_proofs[1].clone(), compressed_unit_proofs[2].clone()],
        opts,
    ).unwrap();
    let recursive_public_value: &RecursionPublicValues<_> =
        compressed_recursive_proof.proof.public_values.as_slice().borrow();
    println!("deferred_hash: {:?}", recursive_public_value.deferred_proofs_digest);
    println!("complete: {:?}", recursive_public_value.is_complete);

    prover.verify_compressed(&compressed_recursive_proof, &recursive_vk).unwrap();
    tracing::info!("verify recursive proof success");
    */

    
        //build 1st recursive proof
        let mut stdin = SP1Stdin::new();
        let unit_vkey_digest = unit_vk.hash_babybear();
        let unit_vkey_digest: [u32; 8] = unit_vkey_digest
            .iter()
            .map(|n| n.as_canonical_u32())
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();
  
        stdin.write(&unit_vkey_digest);
        stdin.write(&unit_vkey_digest);
        stdin.write(&unit_public_values[0].clone());
        stdin.write(&unit_public_values[1].clone());
        stdin.write_proof(compressed_unit_proofs[0].clone(), unit_vk.vk.clone());
        stdin.write_proof(compressed_unit_proofs[1].clone(), unit_vk.vk.clone());
    
    
        tracing::info!("build first recursive proof (core)");
        let first_recursive_proof =
            prover.prove_core(&recursive_pk_d, recursive_program.clone(), &stdin, opts, Default::default()).unwrap();
        // let public_values = verify_proof.public_values.clone();
    
        tracing::info!("compress recursive proof");
        let first_compressed_recursive_proof = prover.compress(
            &recursive_vk,
            first_recursive_proof,
            vec![compressed_unit_proofs[0].clone(), compressed_unit_proofs[1].clone()],
            opts,
        ).unwrap();
        let first_recursive_public_value: &RecursionPublicValues<_> = first_compressed_recursive_proof.proof.public_values.as_slice().borrow();
        tracing::info!("first_recursive_public_value {:#?}", first_recursive_public_value);
  
        prover.verify_compressed(&first_compressed_recursive_proof, &recursive_vk).unwrap();
        tracing::info!("verify first recursive proof success");
    
        tracing::info!("build 2nd recursive proof (core)");
        let mut stdin = SP1Stdin::new();
        let recursive_vkey_digest = recursive_vk.hash_babybear();
        let recursive_vkey_digest: [u32; 8] = recursive_vkey_digest
            .iter()
            .map(|n| n.as_canonical_u32())
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();

        let mut first_recursive_proof_public_value: [u8; 64] = [0; 64];
        first_recursive_proof_public_value[0..32].copy_from_slice(&unit_public_values[0][0..32]);
        first_recursive_proof_public_value[32..64].copy_from_slice(&unit_public_values[1][32..64]);
        tracing::info!("first recursive proof public value: {} ", hex::encode(first_recursive_proof_public_value));

        stdin.write(&recursive_vkey_digest);
        stdin.write(&unit_vkey_digest);
        stdin.write(&first_recursive_proof_public_value.to_vec());
        stdin.write(&unit_public_values[2].clone());
        stdin.write_proof(first_compressed_recursive_proof.clone(), recursive_vk.vk.clone());
        stdin.write_proof(compressed_unit_proofs[2].clone(), unit_vk.vk.clone());    

        let second_recursive_proof =
            prover.prove_core(&recursive_pk_d, recursive_program, &stdin, opts, Default::default()).unwrap();
        // let public_values = verify_proof.public_values.clone();
    
        tracing::info!("compress 2nd recursive proof");
        let second_compressed_recursive_proof = prover.compress(
            &recursive_vk,
            second_recursive_proof,
            vec![first_compressed_recursive_proof.clone(), compressed_unit_proofs[2].clone()],
            opts,
        ).unwrap();
        let second_recursive_public_value: &RecursionPublicValues<_> = second_compressed_recursive_proof.proof.public_values.as_slice().borrow();
        tracing::info!("second_recursive_public_value {:#?}", second_recursive_public_value);
  
        prover.verify_compressed(&second_compressed_recursive_proof, &recursive_vk).unwrap();
        tracing::info!("verify second recursive proof success");
    

}

// fn main() {
//     // Setup the logger.
//     sp1_sdk::utils::setup_logger();
//     dotenv::dotenv().ok();

//     // Parse the command line arguments.
//     let args = Args::parse();

//     if args.execute == args.prove {
//         eprintln!("Error: You must specify either --execute or --prove");
//         std::process::exit(1);
//     }

//     if args.unit == args.recursive {
//         eprintln!("Error: You must specify either --uint or --recursive");
//         std::process::exit(1);
//     }


//     if args.unit && args.execute {
//         // Setup the prover client.
//         let client = ProverClient::from_env();

//         // Setup the inputs.
//         let mut stdin = SP1Stdin::new();
//         stdin.write(&args.header);
//         println!("input: {}", args.header);
    
//         let input = hex::decode(args.header).unwrap();
    
//         let (output, report) = client.execute(UNIT_ELF, &stdin).run().unwrap();
//         println!("Program executed successfully.");

//         // Read the output.
//         let decoded = PublicValuesStruct::abi_decode(output.as_slice(), true).unwrap();
//         let PublicValuesStruct {
//             begin_hash,
//             end_hash,
//         } = decoded;
//         println!("begin_hash: {}", hex::encode(begin_hash));
//         println!("end_hash: {}", hex::encode(end_hash));

//         let mut expected_begin_hash: [u8; 32] = [0; 32];
//         expected_begin_hash.copy_from_slice(&input[4..36]);

//         let expected_end_hash = double_sha256(&input);
//         assert_eq!(begin_hash, expected_begin_hash);
//         assert_eq!(end_hash, expected_end_hash);
//         println!("Values are correct!");

//         // Record the number of cycles executed.
//         println!("Number of cycles: {}", report.total_instruction_count());
//         return;
//     }

//     // if 



//     // if args.execute {
//     //     // Execute the program

       
//     // } else {
//     //     // Setup the program for proving.
//     //     let (pk, vk) = client.setup(FIBONACCI_ELF);

//     //     // Generate the proof
//     //     let proof: sp1_sdk::SP1ProofWithPublicValues = client
//     //         .prove(&pk, &stdin)
//     //         .run()
//     //         .expect("failed to generate proof");

//     //     println!("Successfully generated proof!");

//     //     // Verify the proof.
//     //     client.verify(&proof, &vk).expect("failed to verify proof");

//     //     //TODO, save proof to file
//     //     let path = format!("block_header_uint_{}_{}.proof", args.n, args.n + 1);
//     //     proof.save(&path).expect("Failed to save proof");

//     //     println!("Successfully verified proof!");
//     // }
// }


#[cfg(test)]
mod tests {
    use super::*;
    use std::env;
    use std::path::Path;

    
    #[test]
    fn test_print() {
        println!("hello world");
    }

    #[test]
    fn test_prove() {
   
        let unit_elf = UNIT_ELF;

        // Test program which verifies proofs of a vkey and a list of committed inputs.
        let recursive_elf = RECURSIVE_ELF;

        tracing::info!("initializing prover");
        let prover = SP1Prover::<CpuProverComponents>::new();

        tracing::info!("setup unit elf");
        let (_, unit_pk_d, unit_program, unit_vk) = prover.setup(unit_elf);

        tracing::info!("setup recursive elf");
        let (_, recursive_pk_d, recursive_program, recursive_vk) = prover.setup(recursive_elf);

        
        let opts = SP1ProverOpts::auto();

        tracing::info!("prove headers");
      

        let headers :[String;3] = [
            String::from("01000000b5fbf970bf362cc3203d71022d0764ce966a9d5cee7615354e273624000000008c209cca50575be7aad6faf11c26af9d91fc91f9bf953c1e7d4fca44e44be3fa3d286f49ffff001d2e18e5ed"),
            String::from("010000003c668f799ca5472fd05b8d43c574469fbec46ae3ffec010cdf6ee31100000000a97c6e691b813753248aa4614e4d3a34a3d1471e6ad863a392ccf4687d857a30f92b6f49ffff001d22239e3b"),
            String::from("010000001588b0752fb18960bf8b1728964d091b638e35e3a2c9ed32991da8c300000000cf18302909e57a7687e38d109ff19d01e85fd0f5517ffe821055765193ca51da162f6f49ffff001d16a2ddc4"),
        ];


        for i in 0..headers.len() {
            let mut stdin = SP1Stdin::new();
            // let data = hex::decode(headers[i].clone()).unwrap();
            stdin.write(&headers[i].clone());
            
            let proof =  prover.prove_core(
                &unit_pk_d,
                unit_program.clone(),
                &stdin,
                opts,
                Default::default(),
            ).unwrap();

            let public_values = proof.public_values.to_vec().clone();
            // println!("{} public values {:#?}", i,  public_values);

            tracing::info!("compress unit proofs");
            let compressed_proof = prover.compress(&unit_vk, proof, vec![], opts).unwrap();
            prover.verify_compressed(&compressed_proof, &unit_vk).unwrap();
            println!("{} verify compressed success", i);

        }

      
        // // Generate recursive proof of first subproof.
        // tracing::info!("compress subproof 1");
        // let deferred_reduce_1 = prover.compress(&keccak_vk, deferred_proof_1, vec![], opts)?;
        // prover.verify_compressed(&deferred_reduce_1, &keccak_vk)?;
       
    }




//     fn concate_proofs(
//         begin_hash: &[u8], 
//         relay_hash:&[u8],
//         end_hash : &[u8],
//         first_vk: &SP1VerifyingKey,
//         second_vk : &SP1VerifyingKey,
//         first_proof : sp1_sdk::SP1ProofWithPublicValues,
//         second_proof : sp1_sdk::SP1ProofWithPublicValues,
// ) {
//     //verify proofs
//     let client = ProverClient::from_env();
//     client.verify(&first_proof, &first_vk).expect("failed to verify first proof");
//     client.verify(&second_proof, &second_vk).expect("failed to verify second proof"); 

//     //concatenate proofs
//     let begin_hash_in_first_proof = &first_proof.public_values.as_slice()[0..32];
//     let end_hash_in_first_proof = &first_proof.public_values.as_slice()[32..64];

//     let begin_hash_in_second_proof = &second_proof.public_values.as_slice()[0..32];
//     let end_hash_in_second_proof = &second_proof.public_values.as_slice()[32..64];


//     assert_eq!(begin_hash_in_first_proof, begin_hash);
//     assert_eq!(end_hash_in_first_proof, relay_hash);

//     assert_eq!(begin_hash_in_second_proof, relay_hash);
//     assert_eq!(end_hash_in_second_proof, end_hash);

//     let begin_hash_bytes :[u8;32] = begin_hash.try_into().expect("Slice must be 32 bytes");
//     let end_hash_bytes :[u8;32] = end_hash.try_into().expect("Slice must be 32 bytes");

//     // Encode the public values of the program.
//     let bytes: Vec<u8> = PublicValuesStruct::abi_encode(&PublicValuesStruct {
//         begin_hash: alloy_sol_types::private::FixedBytes(begin_hash_bytes),
//         end_hash: alloy_sol_types::private::FixedBytes(end_hash_bytes),
//     });
//     println!("bytes: {}", hex::encode(bytes));
    
//     // Commit to the public values of the program. The final proof will have a commitment to all the
//     // bytes that were committed to.
//     // sp1_zkvm::io::commit_slice(&bytes);


// }


    #[test]
    fn test_load_proofs() {
        // let client = ProverClient::from_env();
        // let (unit_pk, unit_vk) = client.setup(FIBONACCI_ELF);
        let cwd = env::current_dir().unwrap();
        println!("Current directory: {:?}", cwd);

        let file_path = cwd.join("block_header_uint_0_1.proof");
        if !file_path.exists() {
            panic!("File not found: {:?}", file_path);
        } else {
            println!("File exists: {:?}", file_path);
        }

        let proof_0_1 = sp1_sdk::SP1ProofWithPublicValues::load("block_header_uint_0_1.proof").unwrap();
        println!("{:?}", proof_0_1.public_values);
        let hash0 = &proof_0_1.public_values.as_slice()[0..32];
        let hash1 = &proof_0_1.public_values.as_slice()[32..64];

        let proof_1_2 = sp1_sdk::SP1ProofWithPublicValues::load("block_header_uint_1_2.proof").unwrap();
        let _hash1 = &proof_1_2.public_values.as_slice()[0..32];
        let hash2 = &proof_1_2.public_values.as_slice()[32..64];

        let proof_2_3 = sp1_sdk::SP1ProofWithPublicValues::load("block_header_uint_2_3.proof").unwrap();
        let _hash2 = &proof_2_3.public_values.as_slice()[0..32];
        let hash3 = &proof_2_3.public_values.as_slice()[32..64];

        assert_eq!(hash1, _hash1);
        assert_eq!(hash2, _hash2);
    }
   
//    #[test]
//     fn test_concatenate_proofs_0_1() {

//     let proof_0_1 = sp1_sdk::SP1ProofWithPublicValues::load("block_header_uint_0_1.proof").unwrap();
//     println!("load  proof_0_1 done"); 
    
//     let proof_0_1_clone = proof_0_1.clone();
//     let begin_hash = &proof_0_1_clone.public_values.as_slice()[0..32];
//     let relay_hash = &proof_0_1_clone.public_values.as_slice()[32..64];

//     let proof_1_2 = sp1_sdk::SP1ProofWithPublicValues::load("block_header_uint_1_2.proof").unwrap();
//     let proof_1_2_clone = proof_1_2.clone();
//     let end_hash = &proof_1_2_clone.public_values.as_slice()[32..64];
//     println!("load  proof_1_2 done"); 

//     let client = ProverClient::from_env();
//     let (unit_pk, unit_vk) = client.setup(FIBONACCI_ELF);
//     println!("unit vk setup done");

//     concate_proofs(begin_hash, relay_hash, end_hash, &unit_vk, &unit_vk, proof_0_1, proof_1_2);
        
//     }




}