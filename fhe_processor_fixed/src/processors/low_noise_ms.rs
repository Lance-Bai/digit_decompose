use tfhe::{
    boolean::prelude::PolynomialSize,
    core_crypto::prelude::{
        CastFrom, CastInto, Container, LutCountLog, LweCiphertext, ModulusSwitchOffset,
        MonomialDegree, UnsignedTorus,
    },
};

fn fast_low_noise_pbs_modulus_switch_mask<Scalar: UnsignedTorus + CastInto<usize>>(
    input: Scalar,
    poly_size: PolynomialSize,
    offset: ModulusSwitchOffset,
    lut_count_log: LutCountLog,
) -> (usize, Scalar) {
    // First, do the left shift (we discard the offset msb)
    let mut output = input << offset.0;
    // Start doing the right shift
    output >>= Scalar::BITS - poly_size.log2().0 - 2 + lut_count_log.0;
    // Do the rounding
    output += Scalar::ONE;
    // Finish the right shift
    output >>= 1;
    let bias = input.wrapping_sub(
        output << (Scalar::BITS - poly_size.log2().0 - 1 + lut_count_log.0 - offset.0),
    );
    // Apply the lsb padding
    output <<= lut_count_log.0;
    (<Scalar as CastInto<usize>>::cast_into(output), bias)
}

fn fast_low_noise_pbs_modulus_switch_body<Scalar: UnsignedTorus + CastInto<usize>>(
    input: Scalar,
    bias: Scalar,
    poly_size: PolynomialSize,
    offset: ModulusSwitchOffset,
    lut_count_log: LutCountLog,
) -> usize
where
    Scalar: UnsignedTorus + CastInto<usize> + CastFrom<usize>,
{
    let mut output = input.wrapping_sub(signed_div2(bias)); // b - mu * bias, mu = 1/2
    output <<= offset.0;
    output >>= Scalar::BITS - poly_size.log2().0 - 2 + lut_count_log.0;
    // Do the rounding
    output += Scalar::ONE;
    // Finish the right shift
    output >>= 1;
    // Apply the lsb padding
    output <<= lut_count_log.0;
    <Scalar as CastInto<usize>>::cast_into(output)
}

pub fn fast_low_noise_pbs_modulus_switch<Scalar, InputCont>(
    input: &LweCiphertext<InputCont>,
    poly_size: PolynomialSize,
    offset: ModulusSwitchOffset,
    lut_count_log: LutCountLog,
) -> (Vec<MonomialDegree>, MonomialDegree)
where
    Scalar: UnsignedTorus + CastInto<usize> + CastFrom<usize>,
    InputCont: Container<Element = Scalar>,
{
    let mut bias_acc: Scalar = Scalar::ZERO;

    let mut mask: Vec<MonomialDegree> =
        vec![MonomialDegree(0); input.lwe_size().to_lwe_dimension().0];

    for (element, degree) in input.get_mask().as_ref().iter().zip(mask.iter_mut()) {
        let (output, bias) =
            fast_low_noise_pbs_modulus_switch_mask(*element, poly_size, offset, lut_count_log);
        *degree = MonomialDegree(output);
        bias_acc = bias_acc.wrapping_add(bias);
        //bias_acc += bias;
    }

    let body = MonomialDegree(fast_low_noise_pbs_modulus_switch_body(
        *input.get_body().data,
        bias_acc,
        poly_size,
        offset,
        lut_count_log,
    ));

    (mask, body)
}

fn signed_div2<T: UnsignedTorus + CastInto<usize> + CastFrom<usize>>(x: T) -> T {
    let x_unsigned: usize = x.cast_into();
    let x_signed: i64 = x_unsigned.cast_into();
    let half = x_signed / 2;
    let out: usize = half.cast_into();
    T::cast_from(out)
}

#[cfg(test)]
mod mod_switch_test {
    use tfhe::{
        boolean::prelude::{LweDimension, PolynomialSize, StandardDev},
        core_crypto::{
            fft_impl::common::fast_pbs_modulus_switch,
            prelude::{
                allocate_and_encrypt_new_lwe_ciphertext,
                allocate_and_generate_new_binary_lwe_secret_key, ActivatedRandomGenerator,
                EncryptionRandomGenerator, LutCountLog, ModulusSwitchOffset, Plaintext,
                SecretRandomGenerator,
            },
            seeders::new_seeder,
        },
        shortint::CiphertextModulus,
    };

    use crate::processors::low_noise_ms::fast_low_noise_pbs_modulus_switch;

    #[test]
    fn mod_switch_test_trait() {
        let lwe_dimension = LweDimension(300);
        let noise = StandardDev(0.0000000000000000000000000000000000000001);
        let mut boxed_seeder = new_seeder();
        let seeder = boxed_seeder.as_mut();
        let ciphertext_modulus = CiphertextModulus::new_native();
        let poly_size = PolynomialSize(2048);
        let lut_log_count = LutCountLog(2);

        let mut secret_generator =
            SecretRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed());
        let mut encryption_generator =
            EncryptionRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed(), seeder);

        let key = allocate_and_generate_new_binary_lwe_secret_key::<u64, _>(
            lwe_dimension,
            &mut secret_generator,
        );

        let cipher = allocate_and_encrypt_new_lwe_ciphertext(
            &key,
            Plaintext(5 << 60),
            noise,
            ciphertext_modulus,
            &mut encryption_generator,
        );



        let (mask, body) = fast_low_noise_pbs_modulus_switch(
            &cipher,
            poly_size,
            ModulusSwitchOffset(0),
            lut_log_count,
        );

        println!("our body: {:064b}", body.0);
        println!(
            "ori body: {:064b}",
            fast_pbs_modulus_switch(
                *cipher.get_body().data,
                poly_size,
                ModulusSwitchOffset(0),
                lut_log_count
            )
        );
        let mut temp = body.0 as u64;
        for (a, k) in mask.iter().zip(key.into_container().iter()) {
            temp = temp.wrapping_sub((a.0 as u64) * (*k as u64));
        }
        temp = temp % (1 << 12);
        temp >>= 7;
        temp += 1;
        temp >>= 1;
        println!("result is {:04b}", temp);

        println!("wait")
    }
}
