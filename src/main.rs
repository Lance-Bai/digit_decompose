use refined_tfhe_lhe::generate_accumulator;
use tfhe::core_crypto::prelude::{programmable_bootstrap_lwe_ciphertext, GlweCiphertext};

mod algorithms;
fn main() {
    println!("Hello, world!");
    generate_accumulator(polynomial_size, glwe_size, message_modulus, ciphertext_modulus, delta, f)
}
