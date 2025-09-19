use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};
use fhe_processor::{
    operations::{
        manager::{OperationManager, Step},
        operand::ArithmeticOp,
        operation::OperandType,
    },
    utils::instance::SetII,
};
use rand::Rng;
use std::time::{Duration, Instant};
use tfhe::core_crypto::prelude::CastInto;

const PLAIN_VAL: usize = 500;

struct BenchCase {
    bit_len: usize,
    op: ArithmeticOp,
    mode: OperandType,
    plain_val: Option<usize>,
    name: &'static str,
}

const CASES: &[BenchCase] = &[
    // ---- GTE 16/32 bit ----
    BenchCase { bit_len: 16, op: ArithmeticOp::GTE, mode: OperandType::BothCipher, plain_val: None, name: "GTE (CC) 16bit" },
    BenchCase { bit_len: 16, op: ArithmeticOp::GTE, mode: OperandType::CipherPlain, plain_val: Some(PLAIN_VAL), name: "GTE (CP) 16bit" },
    BenchCase { bit_len: 32, op: ArithmeticOp::GTE, mode: OperandType::BothCipher, plain_val: None, name: "GTE (CC) 32bit" },
    BenchCase { bit_len: 32, op: ArithmeticOp::GTE, mode: OperandType::CipherPlain, plain_val: Some(PLAIN_VAL), name: "GTE (CP) 32bit" },

    // ---- GTE_ORI 16/32 bit ----
    // BenchCase { bit_len: 16, op: ArithmeticOp::GTE_ORI, mode: OperandType::BothCipher, plain_val: None, name: "GTE_ORI (CC) 16bit" },
    BenchCase { bit_len: 16, op: ArithmeticOp::GTEO, mode: OperandType::CipherPlain, plain_val: Some(PLAIN_VAL), name: "GTE_ORI (CP) 16bit" },
    // BenchCase { bit_len: 32, op: ArithmeticOp::GTE_ORI, mode: OperandType::CipherPlain, plain_val: Some(PLAIN_VAL), name: "GTE_ORI (CP) 32bit" },
];

fn run_case(c: &mut Criterion, case: &BenchCase) {
    let slots = match case.mode {
        OperandType::BothCipher => 2,
        OperandType::CipherPlain => 1,
        _ => panic!("Only BothCipher and CipherPlain supported here"),
    };
    let mut manager = OperationManager::new(*SetII, slots + 1, case.bit_len);

    match case.mode {
        OperandType::BothCipher => {
            manager.add_operation(case.op, OperandType::BothCipher, None);
            manager.set_execution_plan(vec![Step::new(0, vec![0, 1], slots)]);
        }
        OperandType::CipherPlain => {
            manager.add_operation(case.op, OperandType::CipherPlain, case.plain_val);
            manager.set_execution_plan(vec![Step::new(0, vec![0], slots)]);
        }
        _ => {}
    }

    c.bench_with_input(BenchmarkId::new(case.name, case.bit_len), &case.bit_len, |b, &_nb| {
        b.iter_custom(|iters| {
            let mut rng = rand::thread_rng();
            let mut total = Duration::ZERO;

            for _ in 0..iters {
                let mask = (1usize << case.bit_len.min(usize::BITS as usize)) - 1;
                let a: usize = rng.gen::<u32>() as usize & mask;

                match case.mode {
                    OperandType::BothCipher => {
                        let b: usize = rng.gen::<u32>() as usize & mask;
                        manager.load_data(a.cast_into(), 0);
                        manager.load_data(b.cast_into(), 1);
                    }
                    OperandType::CipherPlain => {
                        manager.load_data(a.cast_into(), 0);
                    }
                    _ => {}
                }

                let start = Instant::now();
                manager.execute();
                total += start.elapsed();

                let _ = black_box(manager.get_data(slots));
            }

            total
        });
    });
}

fn benches(c: &mut Criterion) {
    for case in CASES {
        run_case(c, case);
    }
}

criterion_group!(
    name = manager_execute;
    config = {
        Criterion::default()
            .sample_size(20)
            .measurement_time(Duration::from_secs(10))
    };
    targets = benches,
);
criterion_main!(manager_execute);
