use std::path::Path;

use alloy_sol_types::SolType;
use clap::Parser;

use lib_2ddoc::TwoDoc;
use sp1_sdk::{ProverClient, SP1Stdin};

/// The ELF (executable and linkable format) file for the Succinct RISC-V zkVM.
pub const EXEC_ELF: &[u8] = include_bytes!("../../../../elf/riscv32im-succinct-zkvm-elf");

/// The arguments for the command.
#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    #[clap(long)]
    execute: bool,

    #[clap(long)]
    prove: bool,

    #[clap(long, default_value = "20")]
    n: u32,
}

fn main() {
    // Setup the logger.
    sp1_sdk::utils::setup_logger();

    // Parse the command line arguments.
    let args = Args::parse();

    if args.execute == args.prove {
        eprintln!("Error: You must specify either --execute or --prove");
        std::process::exit(1);
    }

    // Setup the prover client.
    let client = ProverClient::new();

    // Setup the inputs.
    let mut stdin = SP1Stdin::new();

    //let path = "/Users/matteo/Documents/2ddoc_valid.png";
    let path = "/Users/matteo/Documents/2ddoc_valid_2.png";

    let data = TwoDoc::from_image(path).expect("couldn't read image");

    let public_key = TwoDoc::get_public_key(&data.header).expect("couldnt get public key");

    stdin.write(&data.signed_data);
    stdin.write(&data.signature);
    stdin.write(&public_key);

    if args.execute {
        // Execute the program
        let (mut output, report) = client.execute(EXEC_ELF, stdin).run().unwrap();
        println!(
            "Program executed successfully. Output: {}",
            output.read::<bool>()
        );

        // Record the number of cycles executed.
        println!("Number of cycles: {}", report.total_instruction_count());
    } else {
        // Setup the program for proving.
        let (pk, vk) = client.setup(EXEC_ELF);

        // Generate the proof
        let proof = client
            .prove(&pk, stdin)
            .run()
            .expect("failed to generate proof");

        println!("Successfully generated proof!");

        // Verify the proof.
        client.verify(&proof, &vk).expect("failed to verify proof");
        println!("Successfully verified proof!");
    }
}
