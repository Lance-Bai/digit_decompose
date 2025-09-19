use crate::operations::{
    mask_chunk::{masking_chunk_msb, masking_chunk_msb_decode},
    operand::ArithmeticOp,
};

pub fn get_plain_cipher_cipher(plain_log: usize, op: &ArithmeticOp) -> Vec<usize> {
    let lut_input_size: usize = 1 << (plain_log * 2);
    let mut lut = Vec::with_capacity(lut_input_size);

    for i in 0..lut_input_size {
        let result = op.compute_split(i, plain_log);
        lut.push(result);
    }
    lut
}

pub fn get_plain_lut_cipher_plain(
    plain_log: usize,
    immediate: usize,
    op: &ArithmeticOp,
) -> Vec<usize> {
    let lut_input_size: usize = 1 << (plain_log);
    let mut lut = Vec::with_capacity(lut_input_size);

    for i in 0..lut_input_size {
        let result = op.compute_cipher_plain(i, immediate, plain_log);
        lut.push(result);
    }
    lut
}

pub fn get_plain_lut_plain_cipher(
    plain_log: usize,
    immediate: usize,
    op: &ArithmeticOp,
) -> Vec<usize> {
    let lut_input_size: usize = 1 << (plain_log);
    let mut lut = Vec::with_capacity(lut_input_size);

    for i in 0..lut_input_size {
        let result = op.compute_plain_cipher(i, immediate, plain_log);
        lut.push(result);
    }
    lut
}

pub fn adjust_lut_with_masking(
    plain_lut: &[usize],
    input_bitwidths: &[usize],
    chunk_size: usize,
) -> Vec<usize> {
    let total_bits: usize = input_bitwidths.iter().sum();
    let lut_input_size = 1 << total_bits;
    (0..lut_input_size)
        .map(|i| {
            let mut idxs = Vec::with_capacity(input_bitwidths.len());
            let mut acc = i;
            for &bits in input_bitwidths {
                idxs.push(acc & ((1 << bits) - 1));
                acc >>= bits;
            }
            let mut masked_input = 0usize;
            let mut offset = 0;
            for (block, &bits) in idxs.iter().zip(input_bitwidths) {
                let masked_block = masking_chunk_msb(*block, chunk_size, bits);
                masked_input |= masked_block << offset;
                offset += bits;
            }
            plain_lut[masked_input]
        })
        .collect()
}

/// Decoding version of `adjust_lut_with_masking`
///
/// - `plain_lut`: Plaintext lookup table  
/// - `input_bitwidths`: Array of bitwidths for each input  
/// - `chunk_size`: Masking chunk width  
///
/// # Returns
/// Decoded lookup table
pub fn adjust_lut_with_masking_decode(
    plain_lut: &[usize],
    input_bitwidths: &[usize],
    chunk_size: usize,
) -> Vec<usize> {
    let total_bits: usize = input_bitwidths.iter().sum();
    let lut_input_size = 1 << total_bits;
    (0..lut_input_size)
        .map(|masked_input| {
            let mut blocks = Vec::with_capacity(input_bitwidths.len());
            let mut acc = masked_input;
            for &bits in input_bitwidths {
                blocks.push(acc & ((1 << bits) - 1));
                acc >>= bits;
            }
            let mut decoded_input = 0usize;
            let mut offset = 0;
            for (masked_block, &bits) in blocks.iter().zip(input_bitwidths) {
                let plain_block = masking_chunk_msb_decode(*masked_block, chunk_size, bits);
                decoded_input |= plain_block << offset;
                offset += bits;
            }
            plain_lut[decoded_input]
        })
        .collect()
}

pub fn split_adjusted_lut_by_chunk(
    adjusted_lut: &[usize],
    plain_log: usize,
    chunk_size: usize,
) -> Vec<Vec<usize>> {
    assert!(
        plain_log % chunk_size == 0,
        "plain_log 必须被 chunk_size 整除"
    );
    let segments = plain_log / chunk_size;
    let mask = (1usize << chunk_size) - 1;
    let len = adjusted_lut.len();

    // result_tables[0] is the highest msb segment
    let mut result_tables = vec![Vec::with_capacity(len); segments];

    for &value in adjusted_lut.iter() {
        for msb_seg in 0..segments {
            // high to low
            let shift = (segments - 1 - msb_seg) * chunk_size;
            let chunk = (value >> shift) & mask;
            result_tables[msb_seg].push(chunk);
        }
    }
    result_tables
}

/// # Parameters
/// - `plain_log`: Bitwidth of each input in plaintext (e.g., 8)
/// - `input_bitwidths`: Array of bitwidths for each input (e.g., `vec![8, 8]`)
/// - `chunk_size`: Bitwidth per chunk (e.g., 4)
/// - `op`: Arithmetic operator
///
/// # Returns
/// - `Vec<Vec<usize>>`: Chunked lookup tables (each inner `Vec` represents one chunk’s table)
///
/// # Example
/// ```ignore
/// let chunk_tables = build_split_lut_tables(8, vec![8, 8], 4, &ArithmeticOp::Add);
/// ```
pub fn build_split_lut_tables(
    plain_log: usize,
    input_bitwidths: Vec<usize>,
    chunk_size: usize,
    op: &ArithmeticOp,
) -> Vec<Vec<usize>> {
    let plain_lut = get_plain_cipher_cipher(plain_log, op);

    let adjusted_lut = adjust_lut_with_masking_decode(&plain_lut, &input_bitwidths, chunk_size);

    split_adjusted_lut_by_chunk(&adjusted_lut, plain_log, chunk_size)
}

pub fn build_split_lut_tables_cipher_plain(
    plain_log: usize,
    immediate: usize,
    input_bitwidths: Vec<usize>,
    chunk_size: usize,
    op: &ArithmeticOp,
) -> Vec<Vec<usize>> {
    let plain_lut = get_plain_lut_cipher_plain(plain_log, immediate, op);

    let adjusted_lut = adjust_lut_with_masking_decode(&plain_lut, &input_bitwidths, chunk_size);

    split_adjusted_lut_by_chunk(&adjusted_lut, plain_log, chunk_size)
}

pub fn build_split_lut_tables_plain_cipher(
    plain_log: usize,
    immediate: usize,
    input_bitwidths: Vec<usize>,
    chunk_size: usize,
    op: &ArithmeticOp,
) -> Vec<Vec<usize>> {
    let plain_lut = get_plain_lut_plain_cipher(plain_log, immediate, op);

    let adjusted_lut = adjust_lut_with_masking_decode(&plain_lut, &input_bitwidths, chunk_size);

    split_adjusted_lut_by_chunk(&adjusted_lut, plain_log, chunk_size)
}
