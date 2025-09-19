use crate::operations::{manager::Step, operand::ArithmeticOp, operation::OperandType};

pub struct AverageProgram;

impl AverageProgram {
    pub fn load_operatonis(size: usize) -> Vec<(ArithmeticOp, OperandType, Option<usize>)> {
        let mut operations = Vec::new();
        operations.push((ArithmeticOp::Add, OperandType::BothCipher, None));
        operations.push((ArithmeticOp::Div, OperandType::CipherPlain, Some(size)));
        operations
    }
    pub fn load_programs(size: usize) -> Vec<Step> {
        let mut programs = Vec::new();
        for i in 0..size {
            programs.push(Step::new(0, vec![i, size], size));
        }
        programs.push(Step::new(1, vec![size], size));
        programs
    }
}
