use concrete_fft::c64;
use fhe_processor::processors::pbs::pbs_many_lut_after_ms_before_extract;
use refined_tfhe_lhe::{FourierGlweKeyswitchKey, generate_accumulator, mod_switch};
use tfhe::{
    boolean::{
        ciphertext,
        prelude::{DecompositionBaseLog, DecompositionLevelCount, LweDimension},
    },
    core_crypto::{
        commons::math::decomposition::DecompositionLevel,
        fft_impl::common::fast_pbs_modulus_switch,
        prelude::{
            CastFrom, CastInto, Cleartext, Container, ContainerMut, ContiguousEntityContainer,
            ContiguousEntityContainerMut, FourierLweBootstrapKey, GlweCiphertext,
            GlweCiphertextCount, GlweCiphertextList, LutCountLog, LweCiphertext, LweKeyswitchKey,
            LweSize, ModulusSwitchOffset, MonomialDegree, UnsignedInteger, UnsignedTorus,
            blind_rotate_assign, extract_lwe_sample_from_glwe_ciphertext,
            glwe_ciphertext_cleartext_mul, glwe_ciphertext_cleartext_mul_assign,
            glwe_ciphertext_sub, glwe_ciphertext_sub_assign, keyswitch_lwe_ciphertext,
            lwe_ciphertext_cleartext_mul_assign, lwe_keyswitch,
            multi_bit_programmable_bootstrap_lwe_ciphertext, programmable_bootstrap_lwe_ciphertext,
        },
    },
    shortint::wopbs::CiphertextCount,
};

use crate::algorithms::{
    pbs_many_lut::programmable_bootstrap_lwe_ciphertext_many_lut,
    tools::{make_f1, make_f1_with_b},
};
pub fn digit_decompose_no_padding<Scalar, InputCont, OutputCont, BskCont, KskCont>(
    input: &GlweCiphertext<InputCont>,
    output: &mut GlweCiphertextList<OutputCont>,
    decompose_base_log: DecompositionBaseLog,
    decompose_level: DecompositionLevelCount,
    fourier_bsk: &FourierLweBootstrapKey<BskCont>,
    ksk: &LweKeyswitchKey<KskCont>,
) where
    Scalar: UnsignedTorus + CastInto<usize> + CastFrom<usize> + UnsignedInteger,
    InputCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = Scalar>,
    BskCont: Container<Element = c64>,
    KskCont: Container<Element = Scalar>,
{
    // Function implementation goes here
    assert!(
        output.glwe_ciphertext_count().0 == decompose_level.0,
        "The output glwe ciphertext count must be equal to the decomposition level."
    );
    let fourier_bsk = fourier_bsk.as_view();
    let ciphertext_modulus = input.ciphertext_modulus();
    let glwe_lwe_size = ksk.input_key_lwe_dimension().to_lwe_size();
    let after_ks_lwe_size = ksk.output_key_lwe_dimension().to_lwe_size();
    let glwe_size = fourier_bsk.glwe_size();
    let polynomial_size = fourier_bsk.polynomial_size();
    let ciphertext_count = output.glwe_ciphertext_count().0;

    let mut minuend =
        GlweCiphertext::new(Scalar::ZERO, glwe_size, polynomial_size, ciphertext_modulus);
    let mut subtrahend = minuend.clone();

    let mut extract_input = LweCiphertext::new(Scalar::ZERO, glwe_lwe_size, ciphertext_modulus);
    let mut after_ks = LweCiphertext::new(Scalar::ZERO, after_ks_lwe_size, ciphertext_modulus);

    let mut pbs_result = GlweCiphertextList::new(
        Scalar::ZERO,
        glwe_size,
        polynomial_size,
        GlweCiphertextCount(1),
        ciphertext_modulus,
    );

    //get m0
    glwe_ciphertext_cleartext_mul(
        &mut output.get_mut(0),
        input,
        Cleartext(Scalar::ONE << ((decompose_level.0 - 1) * decompose_base_log.0)),
    );

    // get m1 * B + m0
    glwe_ciphertext_cleartext_mul(
        &mut output.get_mut(1),
        input,
        Cleartext(Scalar::ONE << ((decompose_level.0 - 2) * decompose_base_log.0)),
    );

    extract_lwe_sample_from_glwe_ciphertext(&output.get(0), &mut extract_input, MonomialDegree(0));
    keyswitch_lwe_ciphertext(&ksk, &extract_input, &mut after_ks);

    programmable_bootstrap_lwe_ciphertext_many_lut(
        &mut after_ks,
        &mut pbs_result,
        fourier_bsk,
        LutCountLog(0),
        decompose_base_log.0,
        ciphertext_modulus,
        vec![make_f1_with_b(decompose_base_log.0)],
    );

    glwe_ciphertext_sub_assign(&mut output.get_mut(0), &pbs_result.get(0));

    glwe_ciphertext_cleartext_mul(
        &mut output.get_mut(2),
        &input,
        Cleartext(Scalar::ONE << ((decompose_level.0 - 3) * decompose_base_log.0)),
    );

    extract_lwe_sample_from_glwe_ciphertext(&output.get(1), &mut extract_input, MonomialDegree(0));
    keyswitch_lwe_ciphertext(&ksk, &extract_input, &mut after_ks);
    programmable_bootstrap_lwe_ciphertext_many_lut(
        &mut after_ks,
        &mut pbs_result,
        fourier_bsk,
        LutCountLog(0),
        decompose_base_log.0,
        ciphertext_modulus,
        vec![make_f1_with_b(decompose_base_log.0)],
    );
    glwe_ciphertext_sub_assign(&mut output.get_mut(1), &pbs_result.get(0));
}
