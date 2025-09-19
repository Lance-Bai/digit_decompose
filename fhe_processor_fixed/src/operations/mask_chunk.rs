pub fn masked_bit_extraction(input: usize, chunk_size: usize) -> Vec<usize> {
    let mut result = vec![0; chunk_size];
    for i in 0..chunk_size {
        let mut xor_sum = (input >> i) & 1;
        for j in (i + 1)..chunk_size {
            xor_sum ^= (input >> j) & 1;
        }
        result[i] = xor_sum;
    }
    result
}

pub fn masked_bit_extraction_decode(code: &[usize]) -> Vec<usize> {
    let n = code.len();
    let mut bits = vec![0; n];
    if n == 0 {
        return bits;
    }
    for i in 0..n - 1 {
        bits[i] = code[i] ^ code[i + 1];
    }
    bits[n - 1] = code[n - 1];
    bits
}

pub fn masking_chunk_msb(input: usize, chunk_size: usize, total_bits: usize) -> usize {
    let num_chunks = (total_bits + chunk_size - 1) / chunk_size;
    let mut output_bits = Vec::with_capacity(num_chunks * chunk_size);

    for chunk in 0..num_chunks {
        let shift = chunk * chunk_size;
        let bits_in_chunk = chunk_size.min(total_bits - shift);
        let chunk_value = (input >> shift) & ((1 << bits_in_chunk) - 1);
        let chunk_encoded = masked_bit_extraction(chunk_value, bits_in_chunk);
        output_bits.extend(chunk_encoded);
    }
    vec_to_usize(&output_bits)
}

pub fn masking_chunk_msb_decode(encoded: usize, chunk_size: usize, total_bits: usize) -> usize {
    let num_chunks = (total_bits + chunk_size - 1) / chunk_size;
    let output_bits = usize_to_vec(encoded, num_chunks * chunk_size);

    let mut input_bits = Vec::with_capacity(total_bits);
    for chunk in 0..num_chunks {
        let offset = chunk * chunk_size;
        let bits_in_chunk = chunk_size.min(total_bits - offset);
        let code_slice = &output_bits[offset..offset + bits_in_chunk];
        let decoded_chunk = masked_bit_extraction_decode(code_slice);
        input_bits.extend(&decoded_chunk[..bits_in_chunk]);
    }
    vec_to_usize(&input_bits[..total_bits])
}

pub fn usize_to_vec(mut n: usize, len: usize) -> Vec<usize> {
    let mut bits = vec![0; len];
    for i in 0..len {
        bits[i] = n & 1;
        n >>= 1;
    }
    bits
}

pub fn vec_to_usize(bits: &[usize]) -> usize {
    let mut n = 0usize;
    for (i, &b) in bits.iter().enumerate() {
        n |= b << i;
    }
    n
}

#[cfg(test)]
mod tests {

    use super::*;
    #[test]
    fn test_masking_chunk_msb() {
        let input = 0b1101_1101_1001_1101;
        let chunk_size = 4;
        let total_bits = 16;
        let output = masking_chunk_msb(input, chunk_size, total_bits);
        println!("{:b}->{:b}", input, output);
    }
}
