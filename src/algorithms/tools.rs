use tfhe::core_crypto::prelude::{CastFrom, UnsignedTorus};

fn f1<Scalar: UnsignedTorus + CastFrom<usize>>(x: Scalar, b: usize) -> Scalar {
    let log_scale = Scalar::BITS - b * 2;
    x << (log_scale - 1)
}

// 柯里化：固定 b，得到 Fn(Scalar)->Scalar
pub fn make_f1<Scalar>() -> impl Fn(Scalar, usize) -> Scalar
where
    Scalar: UnsignedTorus + CastFrom<usize>  + Copy,
{
    // 可选：如果你希望一次性固定 b，则用下一段写法（2）
    move |x: Scalar, b: usize| {
        let log_scale = Scalar::BITS - b * 2;
        x << (log_scale - 1)
    }
}

pub fn make_f1_with_b<Scalar>(b: usize) -> impl Fn(Scalar) -> Scalar
where
    Scalar: UnsignedTorus + CastFrom<usize> + Copy,
{
    move |x: Scalar| {
        let log_scale = Scalar::BITS - b * 2;
        x << (log_scale - 1)
    }
}