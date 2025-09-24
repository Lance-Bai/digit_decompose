use tfhe::core_crypto::prelude::{CastFrom, UnsignedTorus};

pub fn make_f1_with_b<Scalar>(b: usize) -> impl Fn(Scalar) -> Scalar
where
    Scalar: UnsignedTorus + CastFrom<usize> + Copy,
{
    move |x: Scalar| {
        let log_scale = Scalar::BITS - b - 2;
        let bound = Scalar::ONE << (b ); //bond = B / 2
        if x < bound {
            Scalar::ONE.wrapping_neg() << log_scale
        } else {
            Scalar::ONE << log_scale
        }
    }
}
