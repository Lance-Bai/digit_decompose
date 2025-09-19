use aligned_vec::{ABox};
use refined_tfhe_lhe::AutomorphKey;
use std::collections::HashMap;
use tfhe::core_crypto::{
    fft_impl::fft64::{c64, crypto::bootstrap::FourierLweBootstrapKeyView},
    prelude::*,
};

use crate::{
    processors::{
        convert::convert_to_ggsw_after_blind_rotate_4_bit_rev_tr,
        lwe_stored_ksk::LweStoredReusedKeyswitchKey,
        lwe_storede_ks::stored_reused_keyswitch_lwe_ciphertext,
    },
    utils::parms::ProcessorParam,
};

use super::{
    
    low_noise_ms::fast_low_noise_pbs_modulus_switch, pbs::pbs_many_lut_after_ms_before_extract,
};

use tfhe::core_crypto::fft_impl::fft64::crypto::ggsw::FourierGgswCiphertextListView;

pub fn circuit_bootstrapping_4_bits_at_once_rev_tr<Scalar, InputCont>(
    input: &LweCiphertext<InputCont>,
    output: &mut FourierGgswCiphertextList<Vec<c64>>,
    fourier_bsk: FourierLweBootstrapKeyView<'_>,
    auto_keys: &HashMap<usize, AutomorphKey<ABox<[c64]>>>,
    ss_key: FourierGgswCiphertextListView,
    ksk: &LweStoredReusedKeyswitchKey<Vec<Scalar>>,
    parms: &ProcessorParam<Scalar>,
) where
    Scalar: UnsignedTorus + CastInto<usize> + CastFrom<usize>,
    InputCont: Container<Element = Scalar>,
{
    let polynomial_size = parms.polynomial_size();
    let cbs_base_log = parms.cbs_base_log();
    let cbs_level = parms.cbs_level();
    let glwe_size = parms.glwe_dimension().to_glwe_size();
    let ciphertext_modulus = parms.ciphertext_modulus();
    let log_lut_count = parms.log_lut_count();
    let num_extracts = parms.extract_size();
    ///////////////////////////////////////////////////////////////////
    let mut small_lwe = LweCiphertext::new(Scalar::ZERO, ksk.output_lwe_size(), ciphertext_modulus);

    let mut acc_glev = GlweCiphertextList::new(
        Scalar::ZERO,
        glwe_size,
        polynomial_size,
        GlweCiphertextCount(cbs_level.0),
        ciphertext_modulus,
    );

    ///////////////////////////////////////////////////////////////////
    stored_reused_keyswitch_lwe_ciphertext(&ksk, &input, &mut small_lwe);
    // let pbs_start = Instant::now();
    let (mask, body) = fast_low_noise_pbs_modulus_switch(
        &small_lwe,
        parms.polynomial_size(),
        ModulusSwitchOffset(0),
        parms.log_lut_count(),
    );
    
    pbs_many_lut_after_ms_before_extract(
        &body,
        &mask,
        &mut acc_glev,
        fourier_bsk,
        log_lut_count,
        cbs_base_log,
        cbs_level,
        num_extracts,
        ciphertext_modulus,
    );
    // println!("pbs time: {:.3?}", pbs_start.elapsed());
    

    let mut ggsw_temp = GgswCiphertext::new(
        Scalar::ZERO,
        glwe_size,
        polynomial_size,
        cbs_base_log,
        cbs_level,
        ciphertext_modulus,
    );
    // let ss_start = Instant::now();
    for (i, mut fourier_ggsw) in output.as_mut_view().into_ggsw_iter().enumerate() {
        convert_to_ggsw_after_blind_rotate_4_bit_rev_tr(
            &acc_glev,
            &mut ggsw_temp,
            i,
            &auto_keys,
            ss_key,
            ciphertext_modulus,
        );
        convert_standard_ggsw_ciphertext_to_fourier(&ggsw_temp, &mut fourier_ggsw);
    }
    // println!("ss time: {:.3?}", ss_start.elapsed());
}
