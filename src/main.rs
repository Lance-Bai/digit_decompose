use std::vec;

use concrete_fft::c64;
use fhe_processor::{
    operations::{manager::concat_ggsw_lists, operation::Operation},
    processors::{
        cbs_4_bits::{self, circuit_bootstrapping_4_bits_at_once_rev_tr},
        key_gen::allocate_and_generate_new_reused_lwe_key,
        lwe_stored_ksk::allocate_and_generate_new_stored_reused_lwe_keyswitch_key,
    },
    utils::instance::SetI,
};
use refined_tfhe_lhe::{
    FourierGlweKeyswitchKey, allocate_and_generate_new_glwe_keyswitch_key, gen_all_auto_keys,
    generate_accumulator, generate_scheme_switching_key,
    keyswitch_lwe_ciphertext_by_glwe_keyswitch,
};
use tfhe::{
    boolean::prelude::{
        DecompositionBaseLog, DecompositionLevelCount, GlweDimension, LweDimension, PolynomialSize,
        StandardDev,
    },
    core_crypto::{
        commons::{
            computation_buffers,
            math::{decomposition::DecompositionLevel, random::Gaussian},
        },
        prelude::{
            ActivatedRandomGenerator, CiphertextModulus, ComputationBuffers,
            ContiguousEntityContainer, ContiguousEntityContainerMut, EncryptionRandomGenerator,
            Fft, FourierGgswCiphertextList, FourierLweBootstrapKey, GlweCiphertext,
            GlweCiphertextCount, GlweCiphertextList, GlweSecretKey, GlweSize, LweCiphertext,
            LweSize, MonomialDegree, PlaintextList, SecretRandomGenerator, SignedDecomposer,
            allocate_and_generate_new_binary_glwe_secret_key,
            allocate_and_generate_new_binary_lwe_secret_key,
            allocate_and_generate_new_lwe_bootstrap_key,
            allocate_and_generate_new_lwe_keyswitch_key,
            convert_standard_lwe_bootstrap_key_to_fourier, decrypt_glwe_ciphertext,
            decrypt_glwe_ciphertext_list, decrypt_lwe_ciphertext, encrypt_glwe_ciphertext,
            encrypt_glwe_ciphertext_assign, extract_lwe_sample_from_glwe_ciphertext,
            par_allocate_and_generate_new_lwe_bootstrap_key,
            par_convert_standard_lwe_bootstrap_key_to_fourier, polynomial,
            programmable_bootstrap_lwe_ciphertext,
        },
        seeders::new_seeder,
    },
};

use crate::algorithms::digit_decompose::*;

mod algorithms;
fn main() {
    println!("Hello, world!");
    let mut boxed_seeder = new_seeder();
    let seeder = boxed_seeder.as_mut();
    let pbs_level = DecompositionLevelCount(1);
    let pbs_base_log = DecompositionBaseLog(26);
    let ks_level = DecompositionLevelCount(6);
    let ks_base_log = DecompositionBaseLog(4);
    let decompose_level = DecompositionLevelCount(4);
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

    let lwe_glwe_key = GlweSecretKey::from_container(lwe_key.as_ref(), PolynomialSize(1024));
    let glwe_glwe_key = GlweSecretKey::from_container(glwe_key.as_ref(), PolynomialSize(1024));

    let ksk_lwe = allocate_and_generate_new_lwe_keyswitch_key(
        &glwe_key.as_lwe_secret_key(),
        &lwe_key,
        ks_base_log,
        ks_level,
        lwe_std_dev,
        ciphertext_modulus,
        &mut encryption_generator,
    );

    let ksk = allocate_and_generate_new_glwe_keyswitch_key(
        &glwe_glwe_key,
        &lwe_glwe_key,
        ks_base_log,
        ks_level,
        lwe_std_dev,
        ciphertext_modulus,
        &mut encryption_generator,
    );

    let mut fourier_ksk = FourierGlweKeyswitchKey::new(
        GlweSize(3),
        GlweSize(2),
        PolynomialSize(1024),
        ks_base_log,
        ks_level,
        refined_tfhe_lhe::FftType::Vanilla,
    );
    refined_tfhe_lhe::convert_standard_glwe_keyswitch_key_to_fourier(&ksk, &mut fourier_ksk);
    drop(ksk);
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

    ////////////////////////////////////////////////////////////////////////////////
    let cbs_params = *SetI;
    let cbs_lwe_dimension = cbs_params.lwe_dimension();
    let cbs_lwe_modular_std_dev = cbs_params.lwe_modular_std_dev();
    let cbs_polynomial_size = cbs_params.polynomial_size();
    let cbs_glwe_dimension = cbs_params.glwe_dimension();
    let cbs_glwe_modular_std_dev = cbs_params.glwe_modular_std_dev();
    let cbs_pbs_base_log = cbs_params.pbs_base_log();
    let cbs_pbs_level = cbs_params.pbs_level();
    let cbs_ks_base_log = cbs_params.ks_base_log();
    let cbs_ks_level = cbs_params.ks_level();
    let cbs_auto_base_log = cbs_params.auto_base_log();
    let cbs_auto_level = cbs_params.auto_level();
    let cbs_auto_fft_type = cbs_params.fft_type_auto();
    let cbs_ss_base_log = cbs_params.ss_base_log();
    let cbs_ss_level = cbs_params.ss_level();
    let cbs_base_log = cbs_params.cbs_base_log();
    let cbs_level = cbs_params.cbs_level();
    let cbs_ciphertext_modulus = cbs_params.ciphertext_modulus();
    let cbs_message_size = cbs_params.message_size();
    let cbs_extract_size = cbs_params.extract_size();
    let cbs_glwe_size = cbs_glwe_dimension.to_glwe_size();
    let cbs_glwe_lwe_size = LweSize(cbs_glwe_dimension.0 * cbs_polynomial_size.0 + 1);

    let glwe_lwe_sk = glwe_key.as_lwe_secret_key();
    let cbs_glwe_key =
        GlweSecretKey::from_container(glwe_key.as_ref().to_vec(), cbs_polynomial_size).to_owned();
    let lwe_sk_after_ks = allocate_and_generate_new_reused_lwe_key(&glwe_lwe_sk, cbs_lwe_dimension);
    let cbs_ksk = allocate_and_generate_new_stored_reused_lwe_keyswitch_key(
        &glwe_lwe_sk,
        &lwe_sk_after_ks,
        cbs_ks_base_log,
        cbs_ks_level,
        cbs_glwe_modular_std_dev,
        cbs_ciphertext_modulus,
        &mut encryption_generator,
    );

    let cbs_bsk = allocate_and_generate_new_lwe_bootstrap_key(
        &lwe_sk_after_ks,
        &cbs_glwe_key,
        cbs_pbs_base_log,
        cbs_pbs_level,
        cbs_glwe_modular_std_dev,
        cbs_ciphertext_modulus,
        &mut encryption_generator,
    );

    let mut cbs_fourier_bsk = FourierLweBootstrapKey::new(
        cbs_bsk.input_lwe_dimension(),
        cbs_bsk.glwe_size(),
        cbs_bsk.polynomial_size(),
        cbs_bsk.decomposition_base_log(),
        cbs_bsk.decomposition_level_count(),
    );
    convert_standard_lwe_bootstrap_key_to_fourier(&cbs_bsk, &mut cbs_fourier_bsk);
    drop(cbs_bsk);

    let auto_keys = gen_all_auto_keys(
        cbs_auto_base_log,
        cbs_auto_level,
        cbs_auto_fft_type,
        &cbs_glwe_key,
        cbs_glwe_modular_std_dev,
        &mut encryption_generator,
    );

    let ss_key = generate_scheme_switching_key(
        &cbs_glwe_key,
        cbs_ss_base_log,
        cbs_ss_level,
        cbs_glwe_modular_std_dev,
        ciphertext_modulus,
        &mut encryption_generator,
    );

    let fourier_ggsw_list = FourierGgswCiphertextList::new(
        vec![
            c64::default();
            cbs_extract_size
                * cbs_polynomial_size.to_fourier_polynomial_size().0
                * cbs_glwe_size.0
                * cbs_glwe_size.0
                * cbs_level.0
        ],
        cbs_extract_size,
        cbs_glwe_size,
        cbs_polynomial_size,
        cbs_base_log,
        cbs_level,
    );
    let mut extract_input = LweCiphertext::new(0_u64, cbs_glwe_lwe_size, ciphertext_modulus);

    let mut input = GlweCiphertext::new(
        0u64,
        glwe_dimension.to_glwe_size(),
        polynomial_size,
        ciphertext_modulus,
    );

    let operation = Operation::new(
        fhe_processor::operations::operand::ArithmeticOp::Mul,
        fhe_processor::operations::operation::OperandType::CipherPlain,
        decompose_base_log.0 * decompose_level.0,
        decompose_base_log.0,
        cbs_polynomial_size,
        1_u64 << (64 - decompose_base_log.0),
        Some(2),
    );

    let mut final_lwes = vec![extract_input.clone(); 4];

    let mut computation_buffer = ComputationBuffers::new();
    let fft = Fft::new(cbs_polynomial_size);
    for num in (0_usize..4096).step_by(7) {
        // println!("num:\t\t\t\t{:012b}", num);
        let num = 0_usize;
        print!("num: {:012b} ", num);
        let mut plain_list =
            PlaintextList::from_container(vec![(num as u64) << 48; polynomial_size.0]);

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
            GlweCiphertextCount(decompose_level.0),
            ciphertext_modulus,
        );

        // digit_decompose_no_padding_ori(
        //     &input,
        //     &mut output,
        //     decompose_base_log,
        //     decompose_level,
        //     &fourier_bsk,
        //     &ksk_lwe,
        //     &glwe_key,
        // );
        digit_decompose_no_padding(
            &input,
            &mut output,
            decompose_base_log,
            decompose_level,
            &fourier_bsk,
            &fourier_ksk,
            &glwe_key,
        );

        // for (i,mut e) in output.iter_mut().enumerate() {
        //     // decrypt_glwe_ciphertext(&glwe_key, &e, &mut plain_list);
        //     // let decode = decomposer.closest_representable(*plain_list.get(0).0);
        //     // print!(" {:04b}", decode >> 60);
        //     let p = num >> (i * 4) & 0b1111;
        //     let local_plain =
        //     PlaintextList::from_container(vec![(p as u64) << 60; polynomial_size.0]);
        //     encrypt_glwe_ciphertext(
        //         &glwe_key,
        //         &mut e,
        //         &local_plain,
        //         glwe_std_dev,
        //         &mut encryption_generator,
        //     );
        // }

        // digit_decompose_with_padding(
        //     &input,
        //     &mut output,
        //     decompose_base_log,
        //     decompose_level,
        //     &fourier_bsk,
        //     &fourier_ksk,
        //     &glwe_key,
        // );
        let mut fourier_ggsw_lists = vec![fourier_ggsw_list.clone(); decompose_level.0];

        for (i, mut e) in output.iter().zip(fourier_ggsw_lists.iter_mut()) {
            extract_lwe_sample_from_glwe_ciphertext(&i, &mut extract_input, MonomialDegree(0));
            circuit_bootstrapping_4_bits_at_once_rev_tr(
                &mut extract_input,
                &mut e,
                cbs_fourier_bsk.as_view(),
                &auto_keys,
                ss_key.as_view(),
                &cbs_ksk,
                &cbs_params,
            );
        }
        fourier_ggsw_lists.reverse();
        let ggsw_bits = concat_ggsw_lists(fourier_ggsw_lists, true);

        operation.vertical_packing_multi_lookup(
            &mut final_lwes,
            &ggsw_bits,
            &fft,
            &mut computation_buffer,
        );
        let decomposer = SignedDecomposer::<u64>::new(
            DecompositionBaseLog(decompose_base_log.0),
            DecompositionLevelCount(1),
        );
        print!("  result:");
        for e in output.iter().rev() {
            decrypt_glwe_ciphertext(&glwe_key, &e, &mut plain_list);
            let decode = decomposer.closest_representable(*plain_list.get(0).0);
            print!(" {:04b}", decode >> 60);
        }
        print!("  final:");
        for e in final_lwes.iter() {
            let result = decrypt_lwe_ciphertext(&cbs_glwe_key.as_lwe_secret_key(), &e);
            let decode = decomposer.closest_representable(result.0);
            print!(" {:04b}", decode >> 60);
        }
        println!()
    }
}
