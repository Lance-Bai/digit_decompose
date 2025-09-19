use std::time::{Duration, Instant};
use criterion::{criterion_group, criterion_main, Criterion, black_box};
use fhe_processor::{operations::manager::OperationManager, programs::{average::AverageProgram, bubble::BubbleProgram, maximum::MaximumProgram, squaresum::SquaresumProgram}, utils::instance::SetI};


fn bench_manager_execute_maximum(c: &mut Criterion) {
    let mut manager = OperationManager::new(*SetI, 6, 8);
    manager.add_operatoins(MaximumProgram::load_operatonis());
    manager.set_execution_plan(MaximumProgram::load_programs(5));

    manager.load_data(16, 0);
    manager.load_data(4, 1);
    manager.load_data(0, 2);
    manager.load_data(9, 3);
    manager.load_data(5, 4);

    c.bench_function("Maximum_Program", |b| {
        b.iter_custom(|iters| {
            let mut total = Duration::ZERO;
            for _ in 0..iters {
                let start = Instant::now();
                manager.execute();
                total += start.elapsed();
                black_box(manager.get_data(5));
            }
            total
        })
    });
}

fn bench_manager_execute_bubble(c: &mut Criterion) {
    let mut manager = OperationManager::new(*SetI, 6, 8);
    manager.add_operatoins(BubbleProgram::load_operatonis());
    manager.set_execution_plan(BubbleProgram::load_programs(5));

    manager.load_data(16, 0);
    manager.load_data(4, 1);
    manager.load_data(0, 2);
    manager.load_data(9, 3);
    manager.load_data(5, 4);

    c.bench_function("Bubble_Program", |b| {
        b.iter_custom(|iters| {
            let mut total = Duration::ZERO;
            for _ in 0..iters {
                let start = Instant::now();
                manager.execute();
                total += start.elapsed();
                black_box(manager.get_data(0));
            }
            total
        })
    });
}

fn bench_manager_execute_squaresum(c: &mut Criterion) {
    let mut manager = OperationManager::new(*SetI, 7, 8);
    manager.add_operatoins(SquaresumProgram::load_operatonis());
    manager.set_execution_plan(SquaresumProgram::load_programs(5));

    manager.load_data(2, 0);
    manager.load_data(4, 1);
    manager.load_data(0, 2);
    manager.load_data(9, 3);
    manager.load_data(5, 4);

    c.bench_function("Squaresum_Program", |b| {
        b.iter_custom(|iters| {
            let mut total = Duration::ZERO;
            for _ in 0..iters {
                manager.load_data(0, 6);

                let start = Instant::now();
                manager.execute();
                total += start.elapsed();

                black_box(manager.get_data(6));
            }
            total
        })
    });
}

fn bench_manager_execute_average(c: &mut Criterion) {
    let mut manager = OperationManager::new(*SetI, 6, 8);
    manager.add_operatoins(AverageProgram::load_operatonis(5));
    manager.set_execution_plan(AverageProgram::load_programs(5));

    manager.load_data(2, 0);
    manager.load_data(4, 1);
    manager.load_data(0, 2);
    manager.load_data(9, 3);
    manager.load_data(5, 4);

    c.bench_function("Average_Program", |b| {
        b.iter_custom(|iters| {
            let mut total = Duration::ZERO;
            for _ in 0..iters {
                manager.load_data(0, 5);

                let start = Instant::now();
                manager.execute();
                total += start.elapsed();

                black_box(manager.get_data(5));
            }
            total
        })
    });
}

criterion_group!(
    programs_execute,
    bench_manager_execute_maximum,
    bench_manager_execute_bubble,
    bench_manager_execute_squaresum,
    bench_manager_execute_average
);
criterion_main!(programs_execute);
