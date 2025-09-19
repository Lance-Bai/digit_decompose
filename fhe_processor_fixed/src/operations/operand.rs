use num_traits::{PrimInt, Unsigned, WrappingAdd, WrappingMul, WrappingSub};
use std::cmp::{max, min};
use std::ops::{BitAnd, BitOr, BitXor, Not, Shl, Shr};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ArithmeticOp {
    Add,
    Sub,
    Mul,
    Mulh,
    Div,
    Mod,
    EQ,
    GT,
    LT,
    GTE,
    LTE,
    MAX,
    MIN,
    RL,
    RR,
    SL,
    SR,
    OR,
    AND,
    XOR,
    NAND,
    NOT,
    MOVE,
    CSEL,
    GTEO,
    SIGN,
}

impl ArithmeticOp {
    pub fn compute<T>(&self, a: T, b: T) -> T
    where
        T: Copy
            + Ord
            + WrappingAdd
            + WrappingSub
            + WrappingMul
            + BitAnd<Output = T>
            + BitOr<Output = T>
            + BitXor<Output = T>
            + Not<Output = T>
            + Shl<u32, Output = T>
            + Shr<u32, Output = T>
            + PrimInt
            + Unsigned
            + From<u8>,
        u64: From<T>,
    {
        match self {
            ArithmeticOp::Add => a.wrapping_add(&b),
            ArithmeticOp::Sub => a.wrapping_sub(&b),
            ArithmeticOp::Mul => a.wrapping_mul(&b),
            ArithmeticOp::Mulh => {
                let wide: u64 = u64::from(a) * u64::from(b);
                let bits = std::mem::size_of::<T>() * 8;
                num_traits::NumCast::from((wide >> bits) as u64).unwrap()
            }
            ArithmeticOp::Div => {
                if b == T::zero() {
                    T::zero()
                } else {
                    a / b
                }
            }
            ArithmeticOp::Mod => {
                if b == T::zero() {
                    T::zero()
                } else {
                    a % b
                }
            }
            ArithmeticOp::EQ => {
                if a == b {
                    T::one()
                } else {
                    T::zero()
                }
            }
            ArithmeticOp::GT => {
                if a > b {
                    T::one()
                } else {
                    T::zero()
                }
            }
            ArithmeticOp::LT => {
                if a < b {
                    T::one()
                } else {
                    T::zero()
                }
            }
            ArithmeticOp::GTE => {
                if a >= b {
                    T::one()
                } else {
                    T::zero()
                }
            }
            ArithmeticOp::GTEO => {
                if a >= b {
                    T::one()
                } else {
                    T::zero()
                }
            }
            ArithmeticOp::LTE => {
                if a <= b {
                    T::one()
                } else {
                    T::zero()
                }
            }
            ArithmeticOp::MAX => max(b, a),
            ArithmeticOp::MIN => min(b, a),
            ArithmeticOp::RL => a.rotate_left(b.to_u32().unwrap()),
            ArithmeticOp::RR => a.rotate_right(b.to_u32().unwrap()),
            ArithmeticOp::SL => {
                a << (b.to_u32().unwrap() & ((std::mem::size_of::<T>() as u32) * 8 - 1))
            }
            ArithmeticOp::SR => {
                a >> (b.to_u32().unwrap() & ((std::mem::size_of::<T>() as u32) * 8 - 1))
            }
            ArithmeticOp::OR => a | b,
            ArithmeticOp::AND => a & b,
            ArithmeticOp::XOR => a ^ b,
            ArithmeticOp::NAND => !(a & b),
            ArithmeticOp::NOT => !a,
            ArithmeticOp::MOVE => a,
            ArithmeticOp::CSEL => a,
            ArithmeticOp::SIGN => a,
        }
    }

    /// one input of width（8、16、32），auto split to a, b
    pub fn compute_split(&self, input: usize, bitwidth: usize) -> usize {
        match bitwidth {
            8 => {
                let mask = 0xFF;
                let a = (input & mask) as u8;
                let b = ((input >> 8) & mask) as u8;
                self.compute(a, b) as usize
            }
            16 => {
                let mask = 0xFFFF;
                let a = (input & mask) as u16;
                let b = ((input >> 16) & mask) as u16;
                self.compute(a, b) as usize
            }
            32 => {
                let mask = 0xFFFF_FFFF;
                let a = (input & mask) as u32;
                let b = ((input >> 32) & mask) as u32;
                self.compute(a, b) as usize
            }
            _ => panic!("Unsupported bitwidth, only 8, 16, 32 are allowed"),
        }
    }

    pub fn compute_cipher_plain(&self, input: usize, immediate: usize, bitwidth: usize) -> usize {
        match bitwidth {
            8 => {
                let a = input as u8;
                let b = immediate as u8;
                self.compute(a, b) as usize
            }
            16 => {
                let a = input as u16;
                let b = immediate as u16;
                self.compute(a, b) as usize
            }
            32 => {
                let a = input as u32;
                let b = immediate as u32;
                self.compute(a, b) as usize
            }
            _ => panic!("Unsupported bitwidth, only 8, 16, 32 are allowed"),
        }
    }

    pub fn compute_plain_cipher(&self, input: usize, immediate: usize, bitwidth: usize) -> usize {
        match bitwidth {
            8 => {
                let a = immediate as u8;
                let b = input as u8;
                self.compute(a, b) as usize
            }
            16 => {
                let a = immediate as u16;
                let b = input as u16;
                self.compute(a, b) as usize
            }
            32 => {
                let a = immediate as u32;
                let b = input as u32;
                self.compute(a, b) as usize
            }
            _ => panic!("Unsupported bitwidth, only 8, 16, 32 are allowed"),
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_arithmetic_op_compute_split_8bit() {
        let input = 0x34u8 as usize | ((0x12u8 as usize) << 8);
        let op = ArithmeticOp::Add;
        assert_eq!(
            op.compute_split(input, 8),
            0x34u8.wrapping_add(0x12u8) as usize
        );

        let op = ArithmeticOp::Mul;
        assert_eq!(
            op.compute_split(input, 8),
            0x34u8.wrapping_mul(0x12u8) as usize
        );

        let op = ArithmeticOp::AND;
        assert_eq!(op.compute_split(input, 8), (0x34u8 & 0x12u8) as usize);
    }

    #[test]
    fn test_arithmetic_op_compute_split_16bit() {
        let input = 0x3456u16 as usize | ((0xABCDu16 as usize) << 16);
        let op = ArithmeticOp::Sub;
        assert_eq!(
            op.compute_split(input, 16),
            0x3456u16.wrapping_sub(0xABCDu16) as usize
        );

        let op = ArithmeticOp::OR;
        assert_eq!(
            op.compute_split(input, 16),
            (0x3456u16 | 0xABCDu16) as usize
        );
    }

    #[test]
    fn test_arithmetic_op_compute_split_32bit() {
        let input = 0x12345678u32 as usize | ((0x9ABCDEF0u32 as usize) << 32);
        let op = ArithmeticOp::XOR;
        assert_eq!(
            op.compute_split(input, 32),
            (0x12345678u32 ^ 0x9ABCDEF0u32) as usize
        );

        let op = ArithmeticOp::MIN;
        assert_eq!(
            op.compute_split(input, 32),
            min(0x12345678u32, 0x9ABCDEF0u32) as usize
        );
    }
}
