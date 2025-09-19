use crate::operations::{manager::Step, operand::ArithmeticOp, operation::OperandType};

pub struct MaximumProgram;

impl MaximumProgram {
    pub fn load_operatonis() -> Vec<(ArithmeticOp, OperandType, Option<usize>)> {
        let mut operations = Vec::new();
        operations.push((ArithmeticOp::MAX, OperandType::BothCipher, None));
        operations
    }
    pub fn load_programs(size: usize) -> Vec<Step> {
        let mut programs = Vec::new();
        for i in 0..size {
            programs.push(Step::new(0, vec![i, size], size)); // buf[size] = max(buf[i], buf[size])
        }
        programs
    }
}
