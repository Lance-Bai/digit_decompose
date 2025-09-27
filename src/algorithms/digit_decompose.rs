use crate::algorithms::tools::make_f3_with_b;
use crate::algorithms::{
    pbs_many_lut::programmable_bootstrap_lwe_ciphertext_many_lut, tools::make_f1_with_b,
};
use concrete_fft::c64;
use refined_tfhe_lhe::{
    FourierGlweKeyswitchKey, GlweKeyswitchKey, keyswitch_lwe_ciphertext_by_glwe_keyswitch,
};
use tfhe::boolean::prelude::LweDimension;
use tfhe::core_crypto::prelude::{
    LweSize, ModulusSwitchOffset, Plaintext, PlaintextList, decrypt_glwe_ciphertext,
    decrypt_lwe_ciphertext, glwe_ciphertext_plaintext_add_assign,
    lwe_ciphertext_plaintext_add_assign, plaintext_list, programmable_bootstrap_lwe_ciphertext,
};
use tfhe::shortint::wopbs::PlaintextCount;
use tfhe::{
    boolean::prelude::{DecompositionBaseLog, DecompositionLevelCount},
    core_crypto::prelude::{
        CastFrom, CastInto, Cleartext, Container, ContainerMut, ContiguousEntityContainer,
        ContiguousEntityContainerMut, FourierLweBootstrapKey, GlweCiphertext, GlweCiphertextCount,
        GlweCiphertextList, GlweSecretKey, LutCountLog, LweCiphertext, LweKeyswitchKey,
        MonomialDegree, SignedDecomposer, UnsignedInteger, UnsignedTorus,
        extract_lwe_sample_from_glwe_ciphertext, glwe_ciphertext_cleartext_mul,
        glwe_ciphertext_sub_assign, keyswitch_lwe_ciphertext,
    },
};
pub fn digit_decompose_no_padding<Scalar, InputCont, OutputCont, BskCont, KskCont>(
    input: &GlweCiphertext<InputCont>,
    output: &mut GlweCiphertextList<OutputCont>,
    decompose_base_log: DecompositionBaseLog, //除去padding的位数,pbs用的是这个加一
    decompose_level: DecompositionLevelCount,
    fourier_bsk: &FourierLweBootstrapKey<BskCont>,
    ksk: &FourierGlweKeyswitchKey<KskCont>,
    glwe_key: &GlweSecretKey<Vec<Scalar>>, // 需要提供 GlweSecretKey
) where
    Scalar: UnsignedTorus + CastInto<usize> + CastFrom<usize> + UnsignedInteger,
    InputCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = Scalar>,
    BskCont: Container<Element = c64>,
    KskCont: Container<Element = c64>,
{
    assert!(
        output.glwe_ciphertext_count().0 == decompose_level.0,
        "The output glwe ciphertext count must be equal to the decomposition level."
    );
    let fourier_bsk = fourier_bsk.as_view();
    let ciphertext_modulus = input.ciphertext_modulus();
    let glwe_lwe_size =
        LweSize(ksk.input_glwe_size().to_glwe_dimension().0 * ksk.polynomial_size().0 + 1);
    let after_ks_lwe_size =
        LweSize(ksk.output_glwe_size().to_glwe_dimension().0 * ksk.polynomial_size().0 + 1);
    let glwe_size = fourier_bsk.glwe_size();
    let polynomial_size = fourier_bsk.polynomial_size();

    let mut extract_input = LweCiphertext::new(Scalar::ZERO, glwe_lwe_size, ciphertext_modulus);
    let mut after_ks = LweCiphertext::new(Scalar::ZERO, after_ks_lwe_size, ciphertext_modulus);

    let mut pbs_result = GlweCiphertextList::new(
        Scalar::ZERO,
        glwe_size,
        polynomial_size,
        GlweCiphertextCount(1),
        ciphertext_modulus,
    );

    let level = decompose_level.0; // 分解层数
    let k = level - 1;
    let base_log = decompose_base_log.0; // base_log
    let lut = vec![make_f1_with_b::<Scalar>(base_log)]; // PBS LUT，仅示例为单一 LUT

    if level >= 1 {
        glwe_ciphertext_cleartext_mul(
            &mut output.get_mut(0),
            input,
            Cleartext(Scalar::ONE << ((level - 1) * base_log)),
        );
    }
    for j in 0..k {
        glwe_ciphertext_cleartext_mul(
            &mut output.get_mut(j + 1),
            input,
            Cleartext(Scalar::ONE << ((level - (j + 2)) * base_log)),
        );

        extract_lwe_sample_from_glwe_ciphertext(
            &output.get(j),
            &mut extract_input,
            MonomialDegree(0),
        );

        keyswitch_lwe_ciphertext_by_glwe_keyswitch(&extract_input, &mut after_ks, &ksk);
        lwe_ciphertext_plaintext_add_assign(
            &mut after_ks,
            Plaintext(Scalar::ONE << (Scalar::BITS - base_log - 1)),
        );
        programmable_bootstrap_lwe_ciphertext_many_lut(
            &mut after_ks,
            &mut pbs_result,
            fourier_bsk,
            LutCountLog(0),
            base_log-1,
            ciphertext_modulus,
            &lut,
        );

        glwe_ciphertext_plaintext_add_assign(
            &mut pbs_result.get_mut(0),
            Plaintext(Scalar::ONE << (Scalar::BITS - base_log - 1)),
        );

        glwe_ciphertext_sub_assign(&mut output.get_mut(j + 1), &pbs_result.get(0));
    }
}

pub fn digit_decompose_with_padding<Scalar, InputCont, OutputCont, BskCont, KskCont>(
    input: &GlweCiphertext<InputCont>,
    output: &mut GlweCiphertextList<OutputCont>,
    decompose_base_log: DecompositionBaseLog, //除去padding的位数,pbs用的是这个加一
    decompose_level: DecompositionLevelCount,
    fourier_bsk: &FourierLweBootstrapKey<BskCont>,
    ksk: &FourierGlweKeyswitchKey<KskCont>,
    glwe_key: &GlweSecretKey<Vec<Scalar>>, // 需要提供 GlweSecretKey
) where
    Scalar: UnsignedTorus + CastInto<usize> + CastFrom<usize> + UnsignedInteger,
    InputCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = Scalar>,
    BskCont: Container<Element = c64>,
    KskCont: Container<Element = c64>,
{
    // Function implementation goes here
    assert!(
        output.glwe_ciphertext_count().0 == decompose_level.0,
        "The output glwe ciphertext count must be equal to the decomposition level."
    );
    let fourier_bsk = fourier_bsk.as_view();
    let ciphertext_modulus = input.ciphertext_modulus();
    let glwe_lwe_size =
        LweDimension(ksk.input_glwe_size().to_glwe_dimension().0 * ksk.polynomial_size().0)
            .to_lwe_size();
    let after_ks_lwe_size =
        LweDimension(ksk.output_glwe_size().to_glwe_dimension().0 * ksk.polynomial_size().0)
            .to_lwe_size();
    let glwe_size = fourier_bsk.glwe_size();
    let polynomial_size = fourier_bsk.polynomial_size();

    let mut extract_input = LweCiphertext::new(Scalar::ZERO, glwe_lwe_size, ciphertext_modulus);
    let mut after_ks = LweCiphertext::new(Scalar::ZERO, after_ks_lwe_size, ciphertext_modulus);

    let mut pbs_result = GlweCiphertextList::new(
        Scalar::ZERO,
        glwe_size,
        polynomial_size,
        GlweCiphertextCount(2),
        ciphertext_modulus,
    );

    let level = decompose_level.0; // 分解层数
    let k = level - 1;
    let base_log = decompose_base_log.0; // base_log
    let lut = vec![
        make_f1_with_b::<Scalar>(base_log),
        make_f3_with_b::<Scalar>(base_log),
    ]; // PBS LUT，仅示例为单一 LUT

    // ---- 1) 只初始化一次：先准备 output[0], output[1] ----
    let mut temp =
        GlweCiphertext::new(Scalar::ZERO, glwe_size, polynomial_size, ciphertext_modulus);
    if level >= 1 {
        glwe_ciphertext_cleartext_mul(
            &mut temp,
            input,
            Cleartext(Scalar::ONE << ((level - 1) * base_log)),
        );
    }
    // ---- 2) 主循环：PBS 于 j，上一步结果减到 j+1（不同 j）----
    for j in 0..k {
        // 从 output[j] 抽样 -> KS -> PBS
        extract_lwe_sample_from_glwe_ciphertext(&temp, &mut extract_input, MonomialDegree(0));

        // let tempp = decrypt_lwe_ciphertext(&glwe_key.as_lwe_secret_key(), &extract_input);
        // let decomposer =
        //     SignedDecomposer::<Scalar>::new(decompose_base_log, DecompositionLevelCount(1));
        // let decode = decomposer.closest_representable(tempp.0);
        // println!("before f1: {:064b}", decode);
        keyswitch_lwe_ciphertext_by_glwe_keyswitch(&extract_input, &mut after_ks, &ksk);

        lwe_ciphertext_plaintext_add_assign(
            &mut after_ks,
            Plaintext(Scalar::ONE << (Scalar::BITS - base_log - 1)),
        );
        programmable_bootstrap_lwe_ciphertext_many_lut(
            &mut after_ks,
            &mut pbs_result,
            fourier_bsk,
            LutCountLog(1),
            base_log-1,
            ciphertext_modulus,
            &lut,
        );

        let decomposer =
            SignedDecomposer::<Scalar>::new(DecompositionBaseLog(8), DecompositionLevelCount(1));
        let mut plain_list = PlaintextList::new(Scalar::ZERO, PlaintextCount(polynomial_size.0));
        decrypt_glwe_ciphertext(&glwe_key, &pbs_result.get(1), &mut plain_list);
        let decode = decomposer.closest_representable(*plain_list.get(0).0);
        println!("output is:\t{:064b}", decode);

        glwe_ciphertext_plaintext_add_assign(
            &mut pbs_result.get_mut(1),
            Plaintext(
                (Scalar::ONE << (Scalar::BITS - base_log - 2))
                    * ((Scalar::ONE << base_log) - Scalar::ONE),
            ),
        );
        println!("added:\t\t\t{:064b}", (Scalar::ONE << (Scalar::BITS - base_log - 2)) * ((Scalar::ONE << base_log) - Scalar::ONE));
        let mut dst = output.get_mut(j);
        let src = pbs_result.get(1);
        dst.as_mut().copy_from_slice(src.as_ref());

        // let decomposer =
        //     SignedDecomposer::<Scalar>::new(DecompositionBaseLog(8), DecompositionLevelCount(1));
        // let mut plain_list = PlaintextList::new(Scalar::ZERO, PlaintextCount(polynomial_size.0));
        // decrypt_glwe_ciphertext(&glwe_key, &pbs_result.get(0), &mut plain_list);
        // let decode = decomposer.closest_representable(*plain_list.get(0).0);
        // println!("before add:\t{:064b}", decode);
        glwe_ciphertext_plaintext_add_assign(
            &mut pbs_result.get_mut(0),
            Plaintext(Scalar::ONE << (Scalar::BITS - base_log - 1)),
        );
        // println!("added:\t\t\t{:064b}", Scalar::ONE << (Scalar::BITS -  base_log - 2));
        // let decomposer =
        //     SignedDecomposer::<Scalar>::new(DecompositionBaseLog(8), DecompositionLevelCount(1));
        // let mut plain_list = PlaintextList::new(Scalar::ZERO, PlaintextCount(polynomial_size.0));
        // decrypt_glwe_ciphertext(&glwe_key, &pbs_result.get(0), &mut plain_list);
        // let decode = decomposer.closest_representable(*plain_list.get(0).0);
        // println!("to be sub:\t{:064b}", decode);

        // 为下一步的“被减数”提前初始化 output[j+2]（若存在）
        glwe_ciphertext_cleartext_mul(
            &mut temp,
            input,
            Cleartext(Scalar::ONE << ((level - (j + 2)) * base_log)),
        );
        // 用 PBS 结果“减到下一段”：minuend = output[j+1], subtrahend = pbs_result[0]
        glwe_ciphertext_sub_assign(&mut temp, &pbs_result.get(0));
    }
}
