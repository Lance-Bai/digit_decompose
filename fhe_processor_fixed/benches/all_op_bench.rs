use criterion::{black_box, criterion_group, criterion_main, Criterion};
use fhe_processor::{
    operations::{
        manager::{OperationManager, Step},
        operand::ArithmeticOp,
        operation::OperandType,
    },
    utils::instance::SetI,
};
use rand::{thread_rng, Rng};
use std::time::{Duration, Instant};


fn is_unary(op: &ArithmeticOp) -> bool {
    matches!(op, ArithmeticOp::NOT | ArithmeticOp::MOVE)
}

fn safe_const_for(op: &ArithmeticOp) -> usize {
    match op {
        ArithmeticOp::Div | ArithmeticOp::Mod => 7, 
        ArithmeticOp::SL | ArithmeticOp::SR | ArithmeticOp::RL | ArithmeticOp::RR => 3, 
        _ => 5,
    }
}

fn make_manager(op: ArithmeticOp, operand: OperandType) -> (OperationManager, usize /*out_idx*/) {
    let mut manager = OperationManager::new(*SetI, 10, 8);
    let unary = is_unary(&op);

    match operand {
        OperandType::BothCipher => {
            if unary {
                manager.add_operation(op, OperandType::CipherPlain, None);
                manager.set_execution_plan(vec![Step::new(0, vec![0], 1)]);
                (manager, 1)
            } else {
                manager.add_operation(op, OperandType::BothCipher, None);
                manager.set_execution_plan(vec![Step::new(0, vec![0, 1], 2)]);
                (manager, 2)
            }
        }
        OperandType::PlainCipher | OperandType::CipherPlain => {
            let k = safe_const_for(&op);
            manager.add_operation(op, operand, Some(k));
            manager.set_execution_plan(vec![Step::new(0, vec![0], 1)]);
            (manager, 1)
        }
    }
}

fn bench_one_combo(c: &mut Criterion, label: &str, op: ArithmeticOp, operand: OperandType) {
    let (mut manager, out_idx) = make_manager(op, operand);

    let mut rng = thread_rng();
    c.bench_function(label, |b| {
        b.iter_custom(|iters| {
            let mut total = Duration::ZERO;
            for _ in 0..iters {
                // 8-bit 随机输入
                let mut a: u32 = rng.gen();
                let mut bval: u32 = rng.gen();
                a %= 1 << 8;
                bval %= 1 << 8;

                match op {
                    ArithmeticOp::Div | ArithmeticOp::Mod => {
                        if bval == 0 {
                            bval = 7;
                        }
                    }
                    ArithmeticOp::SL | ArithmeticOp::SR | ArithmeticOp::RL | ArithmeticOp::RR => {
                        bval %= 8;
                    }
                    _ => {}
                }

                match operand {
                    OperandType::BothCipher => {
                        if is_unary(&op) {
                            manager.load_data(a as usize, 0);
                        } else {
                            manager.load_data(a as usize, 0);
                            manager.load_data(bval as usize, 1);
                        }
                    }
                    OperandType::PlainCipher | OperandType::CipherPlain => {
                        manager.load_data(a as usize, 0);
                    }
                }

                let t0 = Instant::now();
                manager.execute();
                total += t0.elapsed();

                black_box(manager.get_data(out_idx));
            }
            total
        });
    });
}

fn benches_all_ops(c: &mut Criterion) {
    use ArithmeticOp::*;
    let ops: &[ArithmeticOp] = &[
        Add, Sub, Mul, Mulh, Div, Mod, EQ, GT, LT, GTE, LTE, MAX, MIN, RL, RR, SL, SR, OR, AND,
        XOR,
    ];

    let ops_u: &[ArithmeticOp] = &[
        NAND, MOVE
    ];

    let modes: &[(&'static str, OperandType)] = &[
        ("CC", OperandType::BothCipher),
        ("PC", OperandType::PlainCipher),
        ("CP", OperandType::CipherPlain),
    ];
    let modes_u: &[(&'static str, OperandType)] = &[
        ("PC", OperandType::PlainCipher),
        ("CP", OperandType::CipherPlain),
    ];

    for op in ops {
        for (tag, mode) in modes {
            let label = format!("{:?} ({})", op, tag);
            bench_one_combo(c, &label, *op, mode.clone());
        }
    }

    for op in ops_u{
        for (tag, mode) in modes_u {
            let label = format!("{:?} ({})", op, tag);
            bench_one_combo(c, &label, *op, mode.clone());
        }
    }
}

fn config() -> Criterion {
    Criterion::default()
        .sample_size(20)
        .warm_up_time(Duration::from_secs(1))
        .measurement_time(Duration::from_secs(10))
        .configure_from_args()
}
criterion_group! {
    name = benches;
    config = config();  
    targets = benches_all_ops,
}

criterion_main!(benches);
