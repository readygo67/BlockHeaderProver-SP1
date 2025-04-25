
use sp1_sdk::{include_elf, SP1Stdin};
use sp1_prover::{HashableKey, SP1Prover};
use sp1_prover::components::CpuProverComponents;
use sp1_stark::SP1ProverOpts;
use bincode;

// use sp1_recursion_core::air::RecursionPublicValues;
use p3_field::PrimeField32;
use sp1_core_machine::utils::setup_logger;
use std::time::{Duration, SystemTime};


/// The ELF (executable and linkable format) file for the Succinct RISC-V zkVM.
pub const UNIT_ELF: &[u8] = include_elf!("block-header-unit");
pub const RECURSIVE_ELF: &[u8] = include_elf!("block-header-recursive");

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

    let mut compressed_unit_proofs = Vec::new(); 
    let mut unit_public_values = Vec::new();
    for i in 0..headers.len() {
        let mut stdin = SP1Stdin::new();
        stdin.write(&headers[i].clone());
        tracing::info!("build {}th unit proof", i);

        let duration = SystemTime::now();
        let proof =  prover.prove_core(
            &unit_pk_d,
            unit_program.clone(),
            &stdin,
            opts,
            Default::default(),
        ).unwrap();
        tracing::info!("prove {}th unit proof duraiton {:#?}", i, duration.elapsed().unwrap());

        let public_value = proof.public_values.to_vec().clone();
       
        let duration = SystemTime::now();
        let compressed_proof = prover.compress(&unit_vk, proof, vec![], opts).unwrap();
        tracing::info!("compress {}th unit proof diration {:#?}", i,  duration.elapsed().unwrap());

        let duration = SystemTime::now();
        prover.verify_compressed(&compressed_proof, &unit_vk).unwrap();
        tracing::info!("verify {}th unit proof diration {:#?}", i,  duration.elapsed().unwrap());
        
        compressed_unit_proofs.push(compressed_proof.clone());
        unit_public_values.push(public_value.clone());

    }
  
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
    
    let duration = SystemTime::now();
    let first_recursive_proof =
        prover.prove_core(&recursive_pk_d, recursive_program.clone(), &stdin, opts, Default::default()).unwrap();
    tracing::info!("build 1st recursive proof diration {:#?}", duration.elapsed().unwrap());    
    
    let duration = SystemTime::now();
    let first_compressed_recursive_proof = prover.compress(
        &recursive_vk,
        first_recursive_proof.clone(),
        vec![compressed_unit_proofs[0].clone(), compressed_unit_proofs[1].clone()],
        opts,
    ).unwrap();
    tracing::info!("compress 1st recursive proof diration {:#?}", duration.elapsed().unwrap());  


    let duration = SystemTime::now();
    prover.verify_compressed(&first_compressed_recursive_proof, &recursive_vk).unwrap();
    tracing::info!("verify 1st recursive proof diration {:#?}", duration.elapsed().unwrap());  
    
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

    stdin.write(&recursive_vkey_digest);
    stdin.write(&unit_vkey_digest);
    stdin.write(&first_recursive_proof_public_value.to_vec());
    stdin.write(&unit_public_values[2].clone());
    stdin.write_proof(first_compressed_recursive_proof.clone(), recursive_vk.vk.clone());
    stdin.write_proof(compressed_unit_proofs[2].clone(), unit_vk.vk.clone());    

    let duration = SystemTime::now();
    let second_recursive_proof =
        prover.prove_core(&recursive_pk_d, recursive_program, &stdin, opts, Default::default()).unwrap();
    tracing::info!("build 2nd recursive proof duration {:#?}", duration.elapsed().unwrap());   

    let duration = SystemTime::now();
    let second_compressed_recursive_proof = prover.compress(
        &recursive_vk,
        second_recursive_proof,
        vec![first_compressed_recursive_proof.clone(), compressed_unit_proofs[2].clone()],
        opts,
        ).unwrap();
    tracing::info!("compress 2nd recursive proof duration {:#?}", duration.elapsed().unwrap());   
  
    let duration = SystemTime::now();
    prover.verify_compressed(&second_compressed_recursive_proof, &recursive_vk).unwrap();
    tracing::info!("verify 2nd compressed recursive proof duration {:#?}", duration.elapsed().unwrap());   
    
}

