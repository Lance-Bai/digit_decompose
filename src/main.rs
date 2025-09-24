use std::vec;

use fhe_processor::processors::key_gen::allocate_and_generate_new_reused_lwe_key;
use refined_tfhe_lhe::generate_accumulator;
use tfhe::{
    boolean::prelude::{
        DecompositionBaseLog, DecompositionLevelCount, GlweDimension, LweDimension, PolynomialSize,
        StandardDev,
    },
    core_crypto::{
        commons::math::{decomposition::DecompositionLevel, random::Gaussian},
        prelude::{
            ActivatedRandomGenerator, CiphertextModulus, ContiguousEntityContainer,
            EncryptionRandomGenerator, FourierLweBootstrapKey, GlweCiphertext, GlweCiphertextCount,
            GlweCiphertextList, LweCiphertext, PlaintextList, SecretRandomGenerator,
            SignedDecomposer, allocate_and_generate_new_binary_glwe_secret_key,
            allocate_and_generate_new_binary_lwe_secret_key,
            allocate_and_generate_new_lwe_keyswitch_key, decrypt_glwe_ciphertext,
            decrypt_glwe_ciphertext_list, encrypt_glwe_ciphertext, encrypt_glwe_ciphertext_assign,
            par_allocate_and_generate_new_lwe_bootstrap_key,
            par_convert_standard_lwe_bootstrap_key_to_fourier, polynomial,
            programmable_bootstrap_lwe_ciphertext,
        },
        seeders::new_seeder,
    },
};

use crate::algorithms::digit_decompose::digit_decompose_no_padding;

mod algorithms;
fn main() {
    println!("Hello, world!");
    let mut boxed_seeder = new_seeder();
    let seeder = boxed_seeder.as_mut();
    let pbs_level = DecompositionLevelCount(2);
    let pbs_base_log = DecompositionBaseLog(15);
    let ks_level = DecompositionLevelCount(6);
    let ks_base_log = DecompositionBaseLog(4);
    let decompose_level = DecompositionLevelCount(3);
    let decompose_base_log = DecompositionBaseLog(4);
    let glwe_dimension = GlweDimension(1);
    let polynomial_size = PolynomialSize(2048);
    let lwe_dimension = LweDimension(1024);
    let lwe_std_dev = StandardDev(7.50000e-08);
    let glwe_std_dev = StandardDev(0.00000000000000029403601535432533);
    //  let lwe_std_dev = StandardDev(0.000000000000000000000000000000000000000001);
    // let glwe_std_dev = StandardDev(0.000000000000000000000000000000000000000001);
    let ciphertext_modulus = CiphertextModulus::<u64>::new_native();

    let mut secret_generator =
        SecretRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed());
    let mut encryption_generator =
        EncryptionRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed(), seeder);
    let glwe_key = allocate_and_generate_new_binary_glwe_secret_key(
        glwe_dimension,
        polynomial_size,
        &mut secret_generator,
    );
    let lwe_key =
        allocate_and_generate_new_binary_lwe_secret_key(lwe_dimension, &mut secret_generator);
    let ksk = allocate_and_generate_new_lwe_keyswitch_key(
        &glwe_key.as_lwe_secret_key(),
        &lwe_key,
        ks_base_log,
        ks_level,
        lwe_std_dev,
        ciphertext_modulus,
        &mut encryption_generator,
    );
    let bsk = par_allocate_and_generate_new_lwe_bootstrap_key(
        &lwe_key,
        &glwe_key,
        pbs_base_log,
        pbs_level,
        glwe_std_dev,
        ciphertext_modulus,
        &mut encryption_generator,
    );
    let mut fourier_bsk = FourierLweBootstrapKey::new(
        bsk.input_lwe_dimension(),
        bsk.glwe_size(),
        bsk.polynomial_size(),
        bsk.decomposition_base_log(),
        bsk.decomposition_level_count(),
    );
    par_convert_standard_lwe_bootstrap_key_to_fourier(&bsk, &mut fourier_bsk);

    let mut input = GlweCiphertext::new(
        0u64,
        glwe_dimension.to_glwe_size(),
        polynomial_size,
        ciphertext_modulus,
    );

    for num in (0_usize..2048).step_by(3) {
        // println!("num:\t\t\t\t{:012b}", num);
        print!("num: {:012b} ", num);
        let mut plain_list =
            PlaintextList::from_container(vec![(num as u64) << 52; polynomial_size.0]);

        encrypt_glwe_ciphertext(
            &glwe_key,
            &mut input,
            &plain_list,
            glwe_std_dev,
            &mut encryption_generator,
        );

        let mut output = GlweCiphertextList::new(
            0u64,
            glwe_dimension.to_glwe_size(),
            polynomial_size,
            GlweCiphertextCount(3),
            ciphertext_modulus,
        );

        digit_decompose_no_padding(
            &input,
            &mut output,
            decompose_base_log,
            decompose_level,
            &fourier_bsk,
            &ksk,
            &glwe_key,
        );

        let decomposer =
            SignedDecomposer::<u64>::new(decompose_base_log, DecompositionLevelCount(1));
        print!("  result:");
        for e in output.iter().rev() {
            decrypt_glwe_ciphertext(&glwe_key, &e, &mut plain_list);
            let decode = decomposer.closest_representable(*plain_list.get(0).0);
            print!(" {:04b}", decode >> 60);
        }
        println!()
    }
}
