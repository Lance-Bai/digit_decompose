use super::parms::ProcessorParam;
use lazy_static::lazy_static;
use refined_tfhe_lhe::FftType;
use tfhe::core_crypto::prelude::*;

lazy_static! {

    pub static ref SetI: ProcessorParam<u64> = ProcessorParam::new(
        LweDimension(710), // lwe_dimension
        StandardDev(1.525878906e-5), // lwe_modular_std_dev
        PolynomialSize(1024), // polynomial_size
        GlweDimension(2), // glwe_dimension
        StandardDev(4.440892099e-16), // glwe_modular_std_dev
        DecompositionBaseLog(12), // pbs_base_log
        DecompositionLevelCount(3), // pbs_level
        DecompositionBaseLog(4), // ks_base_log
        DecompositionLevelCount(4), // ks_level
        DecompositionBaseLog(10), // auto_base_log
        DecompositionLevelCount(4), // auto_level
        FftType::Split(38), // fft_type_auto
        DecompositionBaseLog(13), // ss_base_log
        DecompositionLevelCount(3), // ss_level
        DecompositionBaseLog(8), // cbs_base_log
        DecompositionLevelCount(2), // cbs_level
        LutCountLog(1), // log_lut_count
        CiphertextModulus::<u64>::new_native(), // ciphertext_modulus
        4, // message_size
        4,
    );

        pub static ref SetII: ProcessorParam<u64> = ProcessorParam::new(
        LweDimension(710), // lwe_dimension
        StandardDev(1.525878906e-5), // lwe_modular_std_dev
        PolynomialSize(1024), // polynomial_size
        GlweDimension(2), // glwe_dimension
        StandardDev(4.440892099e-16), // glwe_modular_std_dev
        DecompositionBaseLog(5), // pbs_base_log
        DecompositionLevelCount(9), // pbs_level
        DecompositionBaseLog(4), // ks_base_log
        DecompositionLevelCount(4), // ks_level
        DecompositionBaseLog(4), // auto_base_log
        DecompositionLevelCount(12), // auto_level
        FftType::Split(38), // fft_type_auto
        DecompositionBaseLog(8), // ss_base_log
        DecompositionLevelCount(6), // ss_level
        DecompositionBaseLog(16), // cbs_base_log
        DecompositionLevelCount(1), // cbs_level
        LutCountLog(0), // log_lut_count
        CiphertextModulus::<u64>::new_native(), // ciphertext_modulus
        4, // message_size
        4,
    );


}
