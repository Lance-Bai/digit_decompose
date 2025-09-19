use tfhe::
    core_crypto::
        prelude::{
            lwe_ciphertext_sub_assign, CastFrom, CastInto, Container, ContainerMut, ContiguousEntityContainer, LweCiphertext, UnsignedInteger,
        }
    
;

use super::lwe_stored_ksk::LweStoredReusedKeyswitchKey;

pub fn stored_reused_keyswitch_lwe_ciphertext<Scalar, KSKCont, InputCont, OutputCont>(
    lwe_keyswitch_key: &LweStoredReusedKeyswitchKey<KSKCont>,
    input_lwe_ciphertext: &LweCiphertext<InputCont>,
    output_lwe_ciphertext: &mut LweCiphertext<OutputCont>,
) where
    Scalar: UnsignedInteger + CastInto<usize> + CastFrom<usize>,
    KSKCont: Container<Element = Scalar>,
    InputCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = Scalar>,
{
    assert!(
        lwe_keyswitch_key.input_key_lwe_dimension()
            == input_lwe_ciphertext.lwe_size().to_lwe_dimension(),
        "Mismatched input LweDimension. \
        LweKeyswitchKey input LweDimension: {:?}, input LweCiphertext LweDimension {:?}.",
        lwe_keyswitch_key.input_key_lwe_dimension(),
        input_lwe_ciphertext.lwe_size().to_lwe_dimension(),
    );
    assert!(
        lwe_keyswitch_key.output_key_lwe_dimension()
            == output_lwe_ciphertext.lwe_size().to_lwe_dimension(),
        "Mismatched output LweDimension. \
        LweKeyswitchKey output LweDimension: {:?}, output LweCiphertext LweDimension {:?}.",
        lwe_keyswitch_key.output_key_lwe_dimension(),
        output_lwe_ciphertext.lwe_size().to_lwe_dimension(),
    );
    assert!(
        lwe_keyswitch_key.ciphertext_modulus() == input_lwe_ciphertext.ciphertext_modulus(),
        "Mismatched CiphertextModulus. \
        LweKeyswitchKey CiphertextModulus: {:?}, input LweCiphertext CiphertextModulus {:?}.",
        lwe_keyswitch_key.ciphertext_modulus(),
        input_lwe_ciphertext.ciphertext_modulus()
    );
    assert!(
        lwe_keyswitch_key.ciphertext_modulus() == output_lwe_ciphertext.ciphertext_modulus(),
        "Mismatched CiphertextModulus. \
        LweKeyswitchKey CiphertextModulus: {:?}, output LweCiphertext CiphertextModulus {:?}.",
        lwe_keyswitch_key.ciphertext_modulus(),
        output_lwe_ciphertext.ciphertext_modulus()
    );
    assert!(
        lwe_keyswitch_key
            .ciphertext_modulus()
            .is_compatible_with_native_modulus(),
        "This operation currently only supports power of 2 moduli"
    );

    // Fill the output ciphertext with zero
    output_lwe_ciphertext.as_mut().fill(Scalar::ZERO);

    // Copy the input body to the output ciphertext
    *output_lwe_ciphertext.get_mut_body().data = *input_lwe_ciphertext.get_body().data;

    //Copy the input mask to the output ciphertext for the first lwe_size elements
    for (src, dst) in input_lwe_ciphertext
        .as_ref()
        .iter()
        .zip(output_lwe_ciphertext.get_mut_mask().as_mut().iter_mut())
        .take(lwe_keyswitch_key.output_key_lwe_dimension().0)
    {
        *dst = *src;
    }

    let decomposition_base: usize = 1 << lwe_keyswitch_key.decomposition_base_log().0;


    for (keyswitch_key_block, &input_mask_element) in lwe_keyswitch_key.iter().zip(
        input_lwe_ciphertext
            .get_mask()
            .as_ref()
            .iter()
            .skip(lwe_keyswitch_key.output_key_lwe_dimension().0),
    ) {

        // Loop over the levels
        let decomposition_item = decompose_to_vev(
            input_mask_element,
            lwe_keyswitch_key.decomposition_base_log().0,
            lwe_keyswitch_key.decomposition_level_count().0,
        );

        let mut base_idx: usize;
        // for decomposed in decomposition_iter {
        for (l_idx, decomposed) in decomposition_item.into_iter().rev().enumerate() {

            base_idx = decomposed
                .wrapping_add((decomposition_base / 2).cast_into())
                .cast_into();

            lwe_ciphertext_sub_assign(
                output_lwe_ciphertext,
                &keyswitch_key_block.get(l_idx * decomposition_base + base_idx),
            );
        }
    }
}

fn my_decompose_one_level<S: UnsignedInteger>(base_log: usize, state: &mut S, mod_b_mask: S) -> S {
    let res = *state & mod_b_mask;
    *state >>= base_log;
    let sign_bit = res >> (base_log - 1);
    if sign_bit == S::ONE {
        *state = state.wrapping_add(S::ONE);
        res.wrapping_sub(S::ONE << base_log)
    } else {
        res
    }
}

fn decompose_to_vev<Scalar: UnsignedInteger>(
    input: Scalar,
    base_log: usize,
    level_count: usize,
) -> Vec<Scalar> {
    let mut state = input;
    let mod_b_mask = (Scalar::ONE << base_log) - Scalar::ONE;
    let mut decomposition_terms = Vec::with_capacity(level_count);

    let non_rep_bit_count: usize = Scalar::BITS - level_count * base_log;
    let shift = non_rep_bit_count - 1;
    // Move the representable bits + 1 to the LSB, with our example :
    //       |-----| 64 - (64 - 12 - 1) == 13 bits
    // 0....0XX...XX
    state >>= shift;
    // Add one to do the rounding by adding the half interval
    state += Scalar::ONE;
    // Discard the LSB which was the one deciding in which direction we round
    // -2 == 111...1110, i.e. all bits are 1 except the LSB which is 0 allowing to zero it
    state &= Scalar::TWO.wrapping_neg();
    // Shift right to remove the last bit
    state >>= 1;

    for _ in 0..level_count {
        let value = my_decompose_one_level(base_log, &mut state, mod_b_mask);
        decomposition_terms.push(value);
    }

    decomposition_terms
}
