use tfhe::core_crypto::prelude::{CastFrom, UnsignedTorus};

// pub fn make_f1_with_b<Scalar>(b: usize) -> impl Fn(Scalar) -> Scalar
// where
//     Scalar: UnsignedTorus + CastFrom<usize> + Copy,
// {
//     move |x: Scalar| {
//         let log_scale = Scalar::BITS - b - 2;
//         // let bound = Scalar::ONE << (b ); //bond = B / 2
//         // if x < bound {
//         //     Scalar::ONE.wrapping_neg() << log_scale
//         // } else {
//         //     Scalar::ONE << log_scale
//         // }
//         Scalar::ONE.wrapping_neg() << log_scale
//     }
// }

// pub fn make_f3_with_b<Scalar>(b: usize) -> impl Fn(Scalar) -> Scalar
// where
//     Scalar: UnsignedTorus + CastFrom<usize> + Copy,
// {
//     move |x: Scalar| {
//         let log_scale = Scalar::BITS - b - 2;
//         let bound = Scalar::ONE << (b ); //bond = B / 2
//         if x < bound {
//             Scalar::ONE.wrapping_neg() << log_scale
//         } else {
//             Scalar::ONE << log_scale
//         }
//     }
// }
#[derive(Copy, Clone)]
enum LutKind {
    F1, // 对应 make_f1_with_b
    F3, // 对应 make_f3_with_b
}

/// 统一的可调用对象：在构造时把与 b 有关的量预计算好
pub struct LutFn {
    kind: LutKind,
    b: usize,
}

impl LutFn {
    /// 构造函数（通用）
    pub fn new<Scalar>(kind: LutKind, b: usize) -> Self
    where
        Scalar: UnsignedTorus + CastFrom<usize> + Copy,
    {

        LutFn { kind, b }
    }

    /// 统一的调用接口 —— 运行时只用 x
    pub fn call<Scalar>(&self, x: Scalar) -> Scalar
    where
        Scalar: UnsignedTorus + CastFrom<usize> + Copy,
    {
        match self.kind {
            LutKind::F1 => {
                Scalar::ONE.wrapping_neg() << Scalar::BITS - self.b - 2
            }
            LutKind::F3 => {
                (Scalar::TWO * x + Scalar::ONE).wrapping_neg()
            }
        }
    }
}

/// 工厂函数：返回同一具体类型 LutFn<Scalar>
pub fn make_f1_with_b<Scalar>(b: usize) -> LutFn
where
    Scalar: UnsignedTorus + CastFrom<usize> + Copy,
{
    LutFn::new::<Scalar>(LutKind::F1, b)
}

pub fn make_f3_with_b<Scalar>(b: usize) -> LutFn
where
    Scalar: UnsignedTorus + CastFrom<usize> + Copy,
{
    LutFn::new::<Scalar>(LutKind::F3, b)
}
