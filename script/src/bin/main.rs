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
use fibonacci_lib::PublicValuesStruct;
use hex;
use sp1_sdk::{include_elf, ProverClient, SP1Stdin};

/// The ELF (executable and linkable format) file for the Succinct RISC-V zkVM.
pub const FIBONACCI_ELF: &[u8] = include_elf!("fibonacci-program");

/// The arguments for the command.
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(long)]
    execute: bool,

    #[arg(long)]
    prove: bool,

    #[arg(long, default_value = "1")]
    n: u32,

    #[arg(long, default_value = "20")]
    header: String,
}

fn main() {
    // Setup the logger.
    sp1_sdk::utils::setup_logger();
    dotenv::dotenv().ok();

    // Parse the command line arguments.
    let args = Args::parse();

    if args.execute == args.prove {
        eprintln!("Error: You must specify either --execute or --prove");
        std::process::exit(1);
    }

    // Setup the prover client.
    let client = ProverClient::from_env();

    // Setup the inputs.
    let mut stdin = SP1Stdin::new();
    stdin.write(&args.header);
    println!("input: {}", args.header);

    let input = hex::decode(args.header).unwrap();

    if args.execute {
        // Execute the program

        let (output, report) = client.execute(FIBONACCI_ELF, &stdin).run().unwrap();
        println!("Program executed successfully.");

        // Read the output.
        let decoded = PublicValuesStruct::abi_decode(output.as_slice(), true).unwrap();
        let PublicValuesStruct {
            begin_hash,
            end_hash,
        } = decoded;
        println!("begin_hash: {}", hex::encode(begin_hash));
        println!("end_hash: {}", hex::encode(end_hash));

        let mut expected_begin_hash: [u8; 32] = [0; 32];
        expected_begin_hash.copy_from_slice(&input[4..36]);

        let expected_end_hash = fibonacci_lib::double_sha256(&input);
        assert_eq!(begin_hash, expected_begin_hash);
        assert_eq!(end_hash, expected_end_hash);
        println!("Values are correct!");

        // Record the number of cycles executed.
        println!("Number of cycles: {}", report.total_instruction_count());
    } else {
        // Setup the program for proving.
        let (pk, vk) = client.setup(FIBONACCI_ELF);

        // Generate the proof
        let proof: sp1_sdk::SP1ProofWithPublicValues = client
            .prove(&pk, &stdin)
            .run()
            .expect("failed to generate proof");

        println!("Successfully generated proof!");

        // Verify the proof.
        client.verify(&proof, &vk).expect("failed to verify proof");

        //TODO, save proof to file
        let path = format!("block_header_uint_{}_{}.proof", args.n, args.n + 1);
        proof.save(&path).expect("Failed to save proof");

        println!("Successfully verified proof!");
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use sp1_prover::{CoreSC, Groth16Bn254Proof, HashableKey, InnerSC, PlonkBn254Proof, SP1Prover,SP1ProvingKey, SP1VerifyingKey, components::SP1ProverComponents};

    
    #[test]
    fn test_print() {
        println!("hello world");
    }

    fn concate_proofs(
        begin_hash: &[u8], 
        relay_hash:&[u8],
        end_hash : &[u8],
        first_vk: &SP1VerifyingKey,
        second_vk : &SP1VerifyingKey,
        first_proof : sp1_sdk::SP1ProofWithPublicValues,
        second_proof : sp1_sdk::SP1ProofWithPublicValues,
) {
    //verify proofs
    let client = ProverClient::from_env();
    client.verify(&first_proof, &first_vk).expect("failed to verify first proof");
    client.verify(&second_proof, &second_vk).expect("failed to verify second proof"); 

    //concatenate proofs
    let begin_hash_in_first_proof = &first_proof.public_values.as_slice()[0..32];
    let end_hash_in_first_proof = &first_proof.public_values.as_slice()[32..64];

    let begin_hash_in_second_proof = &second_proof.public_values.as_slice()[0..32];
    let end_hash_in_second_proof = &second_proof.public_values.as_slice()[32..64];


    assert_eq!(begin_hash_in_first_proof, begin_hash);
    assert_eq!(end_hash_in_first_proof, relay_hash);

    assert_eq!(begin_hash_in_second_proof, relay_hash);
    assert_eq!(end_hash_in_second_proof, end_hash);

    let begin_hash_bytes :[u8;32] = begin_hash.try_into().expect("Slice must be 32 bytes");
    let end_hash_bytes :[u8;32] = end_hash.try_into().expect("Slice must be 32 bytes");

    // Encode the public values of the program.
    let bytes: Vec<u8> = PublicValuesStruct::abi_encode(&PublicValuesStruct {
        begin_hash: alloy_sol_types::private::FixedBytes(begin_hash_bytes),
        end_hash: alloy_sol_types::private::FixedBytes(end_hash_bytes),
    });
    println!("bytes: {}", hex::encode(bytes));
    
    // Commit to the public values of the program. The final proof will have a commitment to all the
    // bytes that were committed to.
    // sp1_zkvm::io::commit_slice(&bytes);


}


    #[test]
    fn test_load_proofs() {
        // let client = ProverClient::from_env();
        // let (unit_pk, unit_vk) = client.setup(FIBONACCI_ELF);

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
   
   #[test]
    fn test_concatenate_proofs_0_1() {

    let proof_0_1 = sp1_sdk::SP1ProofWithPublicValues::load("block_header_uint_0_1.proof").unwrap();
    println!("load  proof_0_1 done"); 
    
    let proof_0_1_clone = proof_0_1.clone();
    let begin_hash = &proof_0_1_clone.public_values.as_slice()[0..32];
    let relay_hash = &proof_0_1_clone.public_values.as_slice()[32..64];

    let proof_1_2 = sp1_sdk::SP1ProofWithPublicValues::load("block_header_uint_1_2.proof").unwrap();
    let proof_1_2_clone = proof_1_2.clone();
    let end_hash = &proof_1_2_clone.public_values.as_slice()[32..64];
    println!("load  proof_1_2 done"); 

    let client = ProverClient::from_env();
    let (unit_pk, unit_vk) = client.setup(FIBONACCI_ELF);
    println!("unit vk setup done");

    concate_proofs(begin_hash, relay_hash, end_hash, &unit_vk, &unit_vk, proof_0_1, proof_1_2);
        
    }




}