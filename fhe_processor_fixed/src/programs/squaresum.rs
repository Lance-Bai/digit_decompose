use crate::operations::{manager::Step, operand::ArithmeticOp, operation::OperandType};

pub struct SquaresumProgram;

impl SquaresumProgram {
    pub fn load_operatonis() -> Vec<(ArithmeticOp, OperandType, Option<usize>)> {
        let mut operations = Vec::new();
        operations.push((ArithmeticOp::Mul, OperandType::BothCipher, None));
        operations.push((ArithmeticOp::Add, OperandType::BothCipher, None));
        operations.push((ArithmeticOp::MOVE, OperandType::BothCipher, None));
        operations
    }
    pub fn load_programs(size: usize) -> Vec<Step> {
        let mut programs = Vec::new();
        for i in 0..size {
            programs.push(Step::new(0, vec![i, i], size));
            programs.push(Step::new(1, vec![size, size + 1], size + 1));
        }
        programs
    }
}
