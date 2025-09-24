use aligned_vec::CACHELINE_ALIGN;
use chrono::offset;
use refined_tfhe_lhe::{gen_blind_rotate_local_assign, glwe_ciphertext_monic_monomial_div};
use tfhe::core_crypto::{
    fft_impl::fft64::{
        c64,
        crypto::{bootstrap::FourierLweBootstrapKeyView, ggsw::FourierGgswCiphertextListView},
    },
    prelude::{polynomial_algorithms::*, *},
};
use tfhe::{
    boolean::prelude::{DecompositionBaseLog, DecompositionLevelCount},
    core_crypto::prelude::{
        CastInto, CiphertextModulus, ComputationBuffers, Container, ContainerMut,
        ContiguousEntityContainerMut, Fft, GlweCiphertextList, GlweCiphertextMutView, LutCountLog,
        LweCiphertext, ModulusSwitchOffset, MonomialDegree, PlaintextList, UnsignedTorus,
        allocate_and_trivially_encrypt_new_glwe_ciphertext,
        programmable_bootstrap_lwe_ciphertext_mem_optimized_requirement,
    },
};

pub fn programmable_bootstrap_lwe_ciphertext_many_lut<Scalar, InputCont, OutputCont, F>(
    lwe_in: &LweCiphertext<InputCont>,
    out_list: &mut GlweCiphertextList<OutputCont>,
    fourier_bsk: FourierLweBootstrapKeyView,
    log_lut_count: LutCountLog,
    message_modulus_log: usize,
    ciphertext_modulus: CiphertextModulus<Scalar>,
    f: &[F],
) where
    Scalar: UnsignedTorus + CastInto<usize> + CastFrom<usize> + UnsignedInteger,
    InputCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = Scalar>,
    F: Fn(Scalar) -> Scalar + Send + Sync,
{
    assert_eq!(
        lwe_in.lwe_size(),
        fourier_bsk.input_lwe_dimension().to_lwe_size()
    );
    assert_eq!(out_list.glwe_size(), fourier_bsk.glwe_size());
    assert_eq!(out_list.polynomial_size(), fourier_bsk.polynomial_size());
    assert!(
        f.len() <= 1 << log_lut_count.0,
        "f.len() must be less than or equal to 2^log_lut_count"
    );

    let polynomial_size = fourier_bsk.polynomial_size();
    let glwe_size = fourier_bsk.glwe_size();

    let half_box_size = polynomial_size.0 / (2_usize << message_modulus_log);
    let box_size = 2 * half_box_size;

    let mut accumulator_scalar = vec![Scalar::ZERO; polynomial_size.0];
    for (i, one_box) in accumulator_scalar.chunks_exact_mut(box_size).enumerate() {
        let x = Scalar::cast_from(i);
        for (p, a) in one_box.iter_mut().enumerate() {
            let func_idx = p % f.len(); // 在 box 内循环使用 f[0], f[1], f[2], ...
            *a = f[func_idx](x); // 形如 f0(i), f1(i), f2(i), f0(i), ...
        }
    }
    // for e in accumulator_scalar.iter().step_by(box_size){
    //     println!("{:064b}", e);
    // }

    for a_i in accumulator_scalar[0..half_box_size].iter_mut() {
        *a_i = (*a_i).wrapping_neg();
    }
    accumulator_scalar.rotate_left(half_box_size);

    let accumulator_plaintext = PlaintextList::from_container(accumulator_scalar);
    let accumulator = allocate_and_trivially_encrypt_new_glwe_ciphertext(
        glwe_size,
        &accumulator_plaintext,
        ciphertext_modulus,
    );

    let mut buffers = ComputationBuffers::new();
    let fft = Fft::new(polynomial_size);
    let fft = fft.as_view();

    buffers.resize(
        programmable_bootstrap_lwe_ciphertext_mem_optimized_requirement::<Scalar>(
            glwe_size,
            polynomial_size,
            fft,
        )
        .unwrap()
        .unaligned_bytes_required(),
    );
    let stack = buffers.stack();

    let (mut local_accumulator_data, stack) =
        stack.collect_aligned(CACHELINE_ALIGN, accumulator.as_ref().iter().copied());
    let mut local_accumulator = GlweCiphertextMutView::from_container(
        &mut *local_accumulator_data,
        polynomial_size,
        ciphertext_modulus,
    );

    gen_blind_rotate_local_assign(
        fourier_bsk,
        local_accumulator.as_mut_view(),
        ModulusSwitchOffset(0),
        log_lut_count,
        lwe_in.as_ref(),
        fft,
        stack,
    );
    for (i, mut glwe) in out_list.iter_mut().enumerate() {
        glwe_ciphertext_monic_monomial_div(&mut glwe, &local_accumulator, MonomialDegree(i));
    }
}
