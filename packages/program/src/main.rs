//! A simple program that takes a number `n` as input, and writes the `n-1`th and `n`th fibonacci
//! number as an output.

// These two lines are necessary for the program to properly compile.
//
// Under the hood, we wrap your main function with some extra code so that it behaves properly
// inside the zkVM.
#![no_main]
sp1_zkvm::entrypoint!(main);

use lib_2ddoc::TwoDoc;

pub fn main() {
    let signed_data = sp1_zkvm::io::read::<Vec<u8>>();
    let signature = sp1_zkvm::io::read::<Vec<u8>>();
    let public_key = sp1_zkvm::io::read::<Vec<u8>>();

    let is_valid = TwoDoc::verify_signature(&signed_data, &signature, &public_key);
    sp1_zkvm::io::commit(&is_valid);
}
