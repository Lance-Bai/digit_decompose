use aligned_vec::CACHELINE_ALIGN;
use refined_tfhe_lhe::glwe_ciphertext_monic_monomial_div;
use dyn_stack::{PodStack, ReborrowMut};

use itertools::izip;
use tfhe::core_crypto::{
    algorithms::polynomial_algorithms::*,
    fft_impl::
        fft64::{crypto::bootstrap::FourierLweBootstrapKeyView, math::fft::FftView}
    ,
    prelude::*,
};
use crate::utils::tools::polynomial_wrapping_monic_monomial_mul_and_subtract;

pub fn pbs_many_lut_after_ms_before_extract<Scalar, OutputCont>(
    body: &MonomialDegree,
    mask: &Vec<MonomialDegree>,
    glev_out: &mut GlweCiphertextList<OutputCont>,
    fourier_bsk: FourierLweBootstrapKeyView<'_>,
    log_lut_count: LutCountLog,
    cbs_base_log: DecompositionBaseLog,
    cbs_level: DecompositionLevelCount,
    num_extract_bits: usize,
    ciphertext_modulus: CiphertextModulus<Scalar>,
) where
    Scalar: UnsignedTorus + CastInto<usize>,
    OutputCont: ContainerMut<Element = Scalar>,
{
    assert_eq!(glev_out.glwe_size(), fourier_bsk.glwe_size());
    assert_eq!(glev_out.polynomial_size(), fourier_bsk.polynomial_size());
    assert_eq!(glev_out.glwe_ciphertext_count().0, cbs_level.0);

    let polynomial_size = fourier_bsk.polynomial_size();
    let glwe_size = fourier_bsk.glwe_size();

    let half_box_size = polynomial_size.0 / (2 << num_extract_bits);
    let lut_count = 1 << log_lut_count.0;

    for (acc_idx, mut glev_chunk) in glev_out.chunks_mut(lut_count).enumerate() {
        let mut accumulator = (0..polynomial_size.0)
            .map(|i| {
                let k = i % lut_count;
                let log_scale = Scalar::BITS - (acc_idx * lut_count + k + 1) * cbs_base_log.0;
                (Scalar::ONE).wrapping_neg() << (log_scale - 1)
            })
            .collect::<Vec<Scalar>>();

        for a_i in accumulator[0..half_box_size].iter_mut() {
            *a_i = (*a_i).wrapping_neg();
        }
        accumulator.rotate_left(half_box_size);

        let accumulator_plaintext = PlaintextList::from_container(accumulator);
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

        blind_rotate_local_assign_after_ms(
            body,
            mask,
            fourier_bsk.as_view(),
            local_accumulator.as_mut_view(),
            fft,
            stack,
        );

        for (i, mut glwe) in glev_chunk.iter_mut().enumerate() {
            glwe_ciphertext_monic_monomial_div(&mut glwe, &local_accumulator, MonomialDegree(i));
        }
    }
}

fn blind_rotate_local_assign_after_ms<Scalar>(
    body: &MonomialDegree,
    mask: &Vec<MonomialDegree>,
    bsk: FourierLweBootstrapKeyView<'_>,
    mut lut: GlweCiphertextMutView<'_, Scalar>,
    fft: FftView<'_>,
    mut stack: PodStack<'_>,
) where
    Scalar: UnsignedTorus + CastInto<usize>,
{
    let lut_poly_size = lut.polynomial_size();
    let ciphertext_modulus = lut.ciphertext_modulus();
    assert!(ciphertext_modulus.is_compatible_with_native_modulus());

    lut.as_mut_polynomial_list()
        .iter_mut()
        .for_each(|mut poly| {
            let (mut tmp_poly, _) = stack
                .rb_mut()
                .make_aligned_raw(poly.as_ref().len(), CACHELINE_ALIGN);

            let mut tmp_poly = Polynomial::from_container(&mut *tmp_poly);
            tmp_poly.as_mut().copy_from_slice(poly.as_ref());
            polynomial_wrapping_monic_monomial_div(&mut poly, &tmp_poly, *body);
        });

    // We initialize the ct_0 used for the successive cmuxes
    let mut ct0 = lut;
    let (mut ct1, mut stack) = stack.make_aligned_raw(ct0.as_ref().len(), CACHELINE_ALIGN);
    let mut ct1 =
        GlweCiphertextMutView::from_container(&mut *ct1, lut_poly_size, ciphertext_modulus);

    for (lwe_mask_element, bootstrap_key_ggsw) in izip!(mask, bsk.into_ggsw_iter()) {


        // we effectively inline the body of cmux here, merging the initial subtraction
        // operation with the monic polynomial multiplication, then performing the external
        // product manually

        // We rotate ct_1 and subtract ct_0 (first step of cmux) by performing
        // ct_1 <- (ct_0 * X^{a_hat}) - ct_0
        for (mut ct1_poly, ct0_poly) in izip!(
            ct1.as_mut_polynomial_list().iter_mut(),
            ct0.as_polynomial_list().iter(),
        ) {
            polynomial_wrapping_monic_monomial_mul_and_subtract(
                &mut ct1_poly,
                &ct0_poly,
                *lwe_mask_element,
            );
        }

        // as_mut_view is required to keep borrow rules consistent
        // second step of cmux
        tfhe::core_crypto::fft_impl::fft64::crypto::ggsw::add_external_product_assign(
            ct0.as_mut_view(),
            bootstrap_key_ggsw,
            ct1.as_view(),
            fft,
            stack.rb_mut(),
        );
    }

    if !ciphertext_modulus.is_native_modulus() {
        // When we convert back from the fourier domain, integer values will contain up to 53
        // MSBs with information. In our representation of power of 2 moduli < native modulus we
        // fill the MSBs and leave the LSBs empty, this usage of the signed decomposer allows to
        // round while keeping the data in the MSBs
        let signed_decomposer = SignedDecomposer::new(
            DecompositionBaseLog(ciphertext_modulus.get_custom_modulus().ilog2() as usize),
            DecompositionLevelCount(1),
        );
        ct0.as_mut()
            .iter_mut()
            .for_each(|x| *x = signed_decomposer.closest_representable(*x));
    }
}
