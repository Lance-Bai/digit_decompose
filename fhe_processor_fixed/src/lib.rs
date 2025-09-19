#[global_allocator]
static GLOBAL: jemallocator::Jemalloc = jemallocator::Jemalloc;
pub mod operations;
pub mod opmized_operations;
pub mod processors;
pub mod programs;
pub mod utils;

#[cfg(test)]
mod manager_tests {
    use std::time::Instant;

    use num_traits::ToPrimitive;
    use rand::Rng;
    use tfhe::core_crypto::prelude::CastInto;

    use crate::{
        operations::{
            manager::{OperationManager, Step},
            operand::ArithmeticOp,
            operation::OperandType,
        },
        programs::{
            average::AverageProgram, bubble::BubbleProgram, maximum::MaximumProgram,
            squaresum::SquaresumProgram,
        },
        utils::instance::{SetI, SetII},
    };
    const SAMPLE_SIZE: usize = 10;
    #[test]
    fn test_manager_maximum() {
        let size = 5_usize;
        let mut manager = OperationManager::new(*SetI, size + 1, 8);
        manager.add_operatoins(MaximumProgram::load_operatonis());
        manager.set_execution_plan(MaximumProgram::load_programs(size));

        manager.load_data(16, 0);
        manager.load_data(4, 1);
        manager.load_data(0, 2);
        manager.load_data(9, 3);
        manager.load_data(5, 4);
        let t = Instant::now();
        for _ in 0..SAMPLE_SIZE {
            manager.execute();
        }

        println!(
            "Execution time: {:.3?}",
            t.elapsed() / SAMPLE_SIZE.cast_into()
        );
        let result = manager.get_data(size);
        println!("Maximum of [16, 4, 0, 9, 5] is {}", result);
    }

    #[test]
    fn test_manager_bubble() {
        let size = 5_usize;
        let mut manager = OperationManager::new(*SetI, size + 1, 8);
        manager.add_operatoins(BubbleProgram::load_operatonis());
        manager.set_execution_plan(BubbleProgram::load_programs(size));

        manager.load_data(16, 0);
        manager.load_data(4, 1);
        manager.load_data(0, 2);
        manager.load_data(9, 3);
        manager.load_data(5, 4);
        let t = Instant::now();
        for _ in 0..SAMPLE_SIZE {
            manager.execute();
        }

        println!(
            "Execution time: {:.3?}",
            t.elapsed() / SAMPLE_SIZE.cast_into()
        );
        print!("[16, 4, 0, 9, 5] after sorting is: [");
        for i in 0..size {
            let result = manager.get_data(i);
            print!("{} ", result);
        }
        println!("]")
    }

    #[test]
    fn test_manager_squaresum() {
        let size = 5_usize;
        let mut manager = OperationManager::new(*SetI, size + 2, 8);
        manager.add_operatoins(SquaresumProgram::load_operatonis());
        manager.set_execution_plan(SquaresumProgram::load_programs(size));

        manager.load_data(2, 0);
        manager.load_data(4, 1);
        manager.load_data(0, 2);
        manager.load_data(9, 3);
        manager.load_data(5, 4);

        let t = Instant::now();
        for _ in 0..SAMPLE_SIZE {
            manager.load_data(0, size + 1); // buf[size] = 0
            manager.execute();
        }

        println!(
            "Execution time: {:.3?}",
            t.elapsed() / SAMPLE_SIZE.cast_into()
        );
        let result = manager.get_data(size + 1);
        println!(
            "Square sum of [2,4,0,9,5] is {}, which should be {}",
            result,
            (2 * 2 + 4 * 4 + 0_usize + 9 * 9 + 5 * 5)
        );
    }

    #[test]
    fn test_manager_average() {
        let size = 5_usize;
        let mut manager = OperationManager::new(*SetI, size + 1, 8);
        manager.add_operatoins(AverageProgram::load_operatonis(size));
        manager.set_execution_plan(AverageProgram::load_programs(size));

        manager.load_data(2, 0);
        manager.load_data(4, 1);
        manager.load_data(0, 2);
        manager.load_data(9, 3);
        manager.load_data(5, 4);

        let t = Instant::now();
        for _ in 0..SAMPLE_SIZE {
            manager.load_data(0, size);
            manager.execute();
        }

        println!(
            "Execution time: {:.3?}",
            t.elapsed() / SAMPLE_SIZE.cast_into()
        );
        let result = manager.get_data(size);
        println!(
            "Average of [2,4,0,9,5] is {}, which should be {}",
            result,
            (2 + 4 + 0 + 9 + 5) / 5_usize
        );
    }

    #[test]
    fn test_manager_large_compare_cc() {
        let size = 2_usize;
        let mut manager = OperationManager::new(*SetII, size + 1, 16);
        manager.add_operation(ArithmeticOp::LT, OperandType::BothCipher, None);
        manager.set_execution_plan(vec![Step::new(0, vec![0, 1], size)]);
        let mut rng = rand::thread_rng();
        let mut count = 0;
        let t = Instant::now();
        for _ in 0..SAMPLE_SIZE {
            let a: u32 = rng.gen();
            let b: u32 = rng.gen();
            let a = a % 65536;
            let b = b % 65536;
            let true_result: usize = if a < b { 1 } else { 0 };
            manager.load_data(a.cast_into(), 0);
            manager.load_data(b.cast_into(), 1);
            manager.execute();
            let result = manager.get_data(size);
            println!(
                " 16-bit-CC-LT({}, {}) = {}, which should be {}",
                a, b, result, true_result
            );

            if result == true_result {
                count = count + 1;
            }
        }
        println!(
            "accuracy: {:.3?}",
            count.to_f64().unwrap() / SAMPLE_SIZE.to_f64().unwrap()
        );
        println!(
            "Execution time: {:.3?}",
            t.elapsed() / SAMPLE_SIZE.cast_into()
        );
    }

    #[test]
    fn test_manager_large_compare_pc() {
        let size = 1_usize;
        let b = 32718_usize;
        let mut manager = OperationManager::new(*SetII, size + 1, 16);
        manager.add_operation(ArithmeticOp::GT, OperandType::CipherPlain, Some(b));
        manager.set_execution_plan(vec![Step::new(0, vec![0], size)]);
        let mut rng = rand::thread_rng();
        let mut count = 0;
        let t = Instant::now();
        for _ in 0..SAMPLE_SIZE {
            let a: u32 = rng.gen();
            let a = a % 65536;
            let true_result: usize = if a > b.cast_into() { 1 } else { 0 };
            manager.load_data(a.cast_into(), 0);
            manager.execute();
            let result = manager.get_data(size);

            println!(
                "16-bit-CP-GT({}, {}) = {}, which should be {}",
                a, b, result, true_result
            );
            if result == true_result {
                count = count + 1;
            }
        }
        println!(
            "accuracy: {:.3?}",
            count.to_f64().unwrap() / SAMPLE_SIZE.to_f64().unwrap()
        );
        println!(
            "Execution time: {:.3?}",
            t.elapsed() / SAMPLE_SIZE.cast_into()
        );
    }

    #[test]
    fn test_manager_sign() {
        let size = 1_usize;
        let b = 1 << 31;
        let mut manager = OperationManager::new(*SetII, size + 1, 32);
        manager.add_operation(ArithmeticOp::SIGN, OperandType::CipherPlain, Some(b));
        manager.set_execution_plan(vec![Step::new(0, vec![0], size)]);
        let mut rng = rand::thread_rng();
        let mut count = 0;
        let t = Instant::now();
        for _ in 0..SAMPLE_SIZE {
            let a: u32 = rng.gen();
            let b: u32 = b.cast_into();
            let true_result: usize = if a > b {
                1
            } else if a == b {
                0
            } else {
                (1 << 32) - 1
            };
            manager.load_data(a.cast_into(), 0);
            manager.execute();
            let result = manager.get_data(size);

            println!(
                " sign({}, {}) = {}, which should be {}",
                a, b, result, true_result
            );

            if result == true_result {
                count = count + 1;
            }
        }
        println!(
            "accuracy: {:.3?}",
            count.to_f64().unwrap() / SAMPLE_SIZE.to_f64().unwrap()
        );
        println!(
            "Execution time: {:.3?}",
            t.elapsed() / SAMPLE_SIZE.cast_into()
        );
    }
}
