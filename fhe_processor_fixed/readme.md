# Artifact for *Tetris*

## Downloading the Artifact

The artifact is available on [anonymous.4open.science](https://anonymous.4open.science/r/artifact_of_fhe_processor/) and can be downloaded using:

```bash
curl -L -o fhe_processor.zip \
  "https://anonymous.4open.science/api/repo/artifact_of_fhe_processor/zip"
```

or

```bash
wget -O fhe_processor.zip \
  "https://anonymous.4open.science/api/repo/artifact_of_fhe_processor/zip"
```

Unzip and enter the workspace:

```bash
unzip fhe_processor.zip -d fhe_processor
cd fhe_processor
```

---

## Environment & Dependencies

- **Rust**: Version 1.79 or later (tested with Rust 1.81 stable)
- **Cargo**: Bundled with Rust toolchain
- **Operating System**: Linux (Ubuntu 24.10 LTS, tested)
- **Memory**: 24 GB (tested PC total size) for most cases and 512 GB (measured on a 1TB server) for all cases; experiments requiring more than 24 GB are detailed in the benchmark section.
- **Other tools**: `wget` or `curl` for artifact download

---

## Quick Start

To quickly try out the FHE processor, you can run the example test defined in [lib.rs](./src/lib.rs).  
Execute the following command:

```bash
cargo test --release --package fhe_processor -- manager_tests --show-output
```

This will run the processor test suite and display the results directly in the console.

---

## [Benchmark Evaluation](./benches/)

### [LUT Time Evaluation](./benches/lut_bench.rs)

This benchmark corresponds to **Table 3: FHE LUT Runtime Results** in the paper.  
It measures the execution time of *n-to-n LUTs* using the same computation pipeline as the FHE processor.  

- Provides two parameter sets: **Set I** and **Set II**  
- Supports precision from **4 to 32 bits**  
- Supports **1–8 threads**  

> **Note:** High-precision tests may require significant time and memory. By default, the maximum precision is set to 24 bits because of the limitition of memory.
To test higher precision, modify the configuration at [these 3 lines](./benches/lut_bench.rs#L292-L294) as follow and gurantee to have enough memory. The chosen of parameter set is also here.

```rust
let ctx = setup_ctx(*SetI); //SetI and SetII can be chosen
let n_vals = [4, 8, 12, 16, 20, 24, 28, 32]; // add 28, 32 bits here
let thread_vals = [1, 2, 4, 8]; // set number of threads allowed maximum during evaluation
```

Run with:

```bash
cargo bench --bench lut_bench
```

- The console output reports the total execution time for each precision–thread group.  
- Detailed iteration results and separated timings for *circuit bootstrapping* and *table lookup* are stored in [log](./target/bench_logs), corresponding to **Table 8: Tetris Performance for Differet Precission**.

---

### [Processor Operations Evaluation](./benches/all_op_bench.rs)

This benchmark corresponds to **Table 9: Instructions Performance Evaluation** in the paper.  
It evaluates all operations with 8-bit inputs under three modes:  

- **cipher–cipher**  
- **cipher–plain**  
- **plain–cipher**

By default, benchmarks run with multithreading enabled.  
For fairness (as in the paper), single-thread performance can be measured with:

```bash
RAYON_NUM_THREADS=1 cargo bench --bench all_op_bench
```

---

### [Typical Programs Evaluation](./benches/program_bench.rs)

This benchmark corresponds to **Table 5: Programs Execution Time** in the paper.  
It evaluates four representative programs on five unsigned 8-bit inputs:  

- **Maximum**: Find the largest value  
- **Bubble Sort**: Sort the inputs in ascending order  
- **Square Sum**: Compute the sum of squared inputs  
- **Average**: Compute the average value  

Run with:

```bash
RAYON_NUM_THREADS=1 cargo bench --bench program_bench
```

Again, single-thread results are used in the paper for comparison.

---

### [Large-Precision Comparison Optimization](./benches/large_op_bench.rs)

This benchmark corresponds to **Table 6: Performance of Optimized GTE** in the paper.  
It compares optimized and trivial implementations of comparison instructions.  

- Only **GTE** is tested, since all comparisons share the same implementation.  
- **GTEO** is the trivial version.

Run with:

```bash
RAYON_NUM_THREADS=1 cargo bench --bench large_op_bench
```

> **Note:** By default setting we comment cases of 16-bit both cipher GTEO and 32-bit cipher-plain GTEO for its require large memory. Uncomment [these lines](./benches/large_op_bench.rs#L32-L34) to enable these cases.

---

## [Related Work](./related_work/)

We include several public baselines under `./related_work/`. Each baseline is evaluated using its own artifact/benchmarks, and we report the corresponding timing.

### [PBS Method LUT](./related_work/ccs24/README_CCS.md)

Implementation of *programmable bootstrapping (PBS)*–based LUT from  
**“New Secret Keys for Enhanced Performance in (T)FHE”** ([ePrint 2023/979](https://eprint.iacr.org/2023/979)), enabling high-precision programmable bootstrapping.

**Run**

```bash
make bench_ccs_2024_fft_shrinking_ks
```

**Output**
The reported time corresponds to the LUT evaluation time.

---

### [CMux-Tree Method LUT](./related_work/ccs25/README.md)

Implementation of **“Refined TFHE Leveled Homomorphic Evaluation and Its Application”**
([ePrint 2024/1318](https://eprint.iacr.org/2024/1318)), representing the state of the art for CMux-tree–based LUT evaluation.
This artifact reports timings for two stages that we combine to obtain total *n-to-n* LUT time:

1. **GGSW extraction (input encryption)**

   ```bash
   cargo bench --bench bench_integer_input_lhe
   ```

   The printed time corresponds to **4 input bits**. For higher precision *n* (multiple of 4), scale linearly:

   - 8 bits → ×2
   - 12 bits → ×3
   - 16 bits → ×4
     i.e., `ceil(n / 4)` multiples.

2. **LUT evaluation**

   ```bash
   cargo bench --bench bench_lut_eval
   ```

   The benchmark reports **8→4** table-lookup time. For **n→n** LUTs (with 4-bit chunking), scale by the number of output chunks (e.g., 8→8 ≈ 2× the 8→4 time).

**Total n-to-n LUT time**
Sum the scaled **GGSW extraction time** and the scaled **LUT evaluation time**.

---

### [PBS-Tree Method Processor](./related_work/tches25/README.md)

Implementation of **“Designing a General-Purpose 8-bit (T)FHE Processor Abstraction”**
([ePrint 2024/1201](https://eprint.iacr.org/2024/1201)), which uses 4→4 and 8→8 PBS-tree–based LUT instructions. We derive LUT timing from the reported instruction timings.

**Build & Run**

```bash
git clone https://github.com/tfhe/tfhe.git
cd tfhe
git apply ../patch_fft.patch        # if applicable
make -j8

cd ..
cmake -S . -B ./build
cd build
make -j8

../bin/tches 42 5 12 203 127
```

**Output**
The printed times are used both for instruction-level comparison and for deriving LUT timings.

---

### [CKKS Functional Bootstrapping (ckks)](./related_work/ckks/README.md)

Implementation corresponding to **“General Functional Bootstrapping using CKKS”**  
([ePrint 2024/1623](https://eprint.iacr.org/2024/1623)). This baseline enables *functional bootstrapping* in CKKS, allowing LUT-like evaluation. We follow the authors’ evaluation setup and report the relevant FB/LUT timings.

**Build & Run**

```bash
mkdir build && cd build
cmake ..
make -j8
./bin/examples/pke/ckks-functional-bootstrapping
```

The printed time is the time to finish a 8-bit LUT.

---

## [Security Analysis](./security_analysis.py)

This bench estimate the security level of Tetris with some common attack. 

---