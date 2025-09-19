use crate::operations::{manager::Step, operand::ArithmeticOp, operation::OperandType};

pub struct BubbleProgram;

impl BubbleProgram {
    pub fn load_operatonis() -> Vec<(ArithmeticOp, OperandType, Option<usize>)> {
        let mut operations = Vec::new();
        operations.push((ArithmeticOp::MAX, OperandType::BothCipher, None));
        operations.push((ArithmeticOp::MIN, OperandType::BothCipher, None));
        operations.push((ArithmeticOp::MOVE, OperandType::BothCipher, None));
        operations
    }
    pub fn load_programs(size: usize) -> Vec<Step> {
        let mut programs = Vec::new();
        for i in (0..size).rev() {
            for j in 0..i {
                programs.push(Step::new(0, vec![j, j + 1], size)); // buf[size] = max(buf[j], buf[j+1])
                programs.push(Step::new(1, vec![j, j + 1], j)); // buf[j] = min(buf[j], buf[j+1])
                programs.push(Step::new(2, vec![size], j + 1)); // buf[j+1] = buf[size]
            }
        }
        programs
    }
}
