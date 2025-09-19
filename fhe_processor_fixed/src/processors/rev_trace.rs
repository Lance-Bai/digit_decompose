use std::collections::HashMap;

use aligned_vec::ABox;
use refined_tfhe_lhe::{glwe_ciphertext_clone_from, glwe_ciphertext_mod_raise_from_non_native_power_of_two_to_native, glwe_ciphertext_mod_switch_from_native_to_non_native_power_of_two, AutomorphKey};
use concrete_fft::c64;
use tfhe::core_crypto::prelude::{glwe_ciphertext_add_assign, CiphertextModulus, ContainerMut, GlweCiphertext, GlweCiphertextOwned, UnsignedInteger, UnsignedTorus};



pub fn rev_trace_assign<Scalar, Cont>(
    input: &mut GlweCiphertext<Cont>,
    auto_keys: &HashMap<usize, AutomorphKey<ABox<[c64]>>>,
) where
    Scalar: UnsignedTorus,
    Cont: ContainerMut<Element=Scalar>,
{
    let glwe_size = input.glwe_size();
    let polynomial_size = input.polynomial_size();
    let ciphertext_modulus = input.ciphertext_modulus();

    let mut buf = GlweCiphertextOwned::new(Scalar::ZERO, glwe_size, polynomial_size, ciphertext_modulus);
    let mut out: GlweCiphertext<Vec<Scalar>> = GlweCiphertext::new(Scalar::ZERO, glwe_size, polynomial_size, ciphertext_modulus);
    glwe_ciphertext_clone_from(&mut out, input);

    let log_polynomial_size = polynomial_size.0.ilog2() as usize;
    for i in (1..=(log_polynomial_size)).rev() {
        let k = polynomial_size.0 / (1 << (i - 1)) + 1;
        let auto_key = auto_keys.get(&k).unwrap();
        mod_switch_one_bit_then_rise_back(&mut out);
        auto_key.auto(&mut buf, &out);
        glwe_ciphertext_add_assign(&mut out, &buf);
    }

    glwe_ciphertext_clone_from(input, &out);
}

fn mod_switch_one_bit_then_rise_back<Scalar, Cont>(
    input: &mut GlweCiphertext<Cont>,
) where
    Scalar: UnsignedInteger,
    Cont: ContainerMut<Element=Scalar>,
{
    assert!(
        input.ciphertext_modulus().is_native_modulus(),
        "input ciphertext modulus is not native"
    );

    let polynomial_size = input.polynomial_size();



    let log_small_q = Scalar::BITS - 1 as usize;
    let small_ciphertext_modulus = CiphertextModulus::<Scalar>::try_new_power_of_2(log_small_q).unwrap();
    let glwe_size = input.glwe_size();

    let mut buf = GlweCiphertext::new(Scalar::ZERO, glwe_size, polynomial_size, small_ciphertext_modulus);

    glwe_ciphertext_mod_switch_from_native_to_non_native_power_of_two(&input, &mut buf);
    glwe_ciphertext_mod_raise_from_non_native_power_of_two_to_native(&buf, input);
}