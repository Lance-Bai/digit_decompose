use tfhe::{
    boolean::prelude::LweDimension,
    core_crypto::
        prelude::{
            Container, LweSecretKey, LweSecretKeyOwned, UnsignedTorus,
        }
    ,
};

pub fn allocate_and_generate_new_reused_lwe_key<Scalar, InputCont>(
    input_lwe_sk: &LweSecretKey<InputCont>,
    new_dimension: LweDimension,
) -> LweSecretKeyOwned<Scalar>
where
    Scalar: UnsignedTorus + Copy,
    InputCont: Container<Element = Scalar>,
{
    assert!(
        new_dimension.0 <= input_lwe_sk.lwe_dimension().0,
        "New LWE dimension must be less than the input LWE dimension. \
         New: {:?}, Input: {:?}",
        new_dimension,
        input_lwe_sk.lwe_dimension()
    );
    let mut lwe_secret_key = LweSecretKeyOwned::new_empty_key(Scalar::ZERO, new_dimension);

    // copy the fitst n elemnet from old to new
    let src = &input_lwe_sk.as_ref()[..new_dimension.0];
    let dst = &mut lwe_secret_key.as_mut()[..new_dimension.0];
    dst.copy_from_slice(src);

    lwe_secret_key
}