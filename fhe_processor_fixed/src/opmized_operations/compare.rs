use concrete_fft::c64;
use tfhe::{
    core_crypto::prelude::{
        cmux_assign_mem_optimized, cmux_assign_mem_optimized_requirement,
        extract_lwe_sample_from_glwe_ciphertext, trivially_encrypt_glwe_ciphertext,
        trivially_encrypt_lwe_ciphertext, ComputationBuffers, Fft, FourierGgswCiphertext,
        FourierGgswCiphertextList, GlweCiphertext, LweCiphertext, MonomialDegree, Plaintext,
        PlaintextList,
    },
    shortint::wopbs::PlaintextCount,
};

use crate::operations::operand::ArithmeticOp;

pub fn opmized_compare_bothcipher(
    input: &Vec<FourierGgswCiphertextList<Vec<c64>>>,
    lwe_outs: &mut [LweCiphertext<Vec<u64>>],
    op: ArithmeticOp,
    fft: &Fft,
) {
    let glwe_size = input[0].glwe_size();
    let poly_size = input[0].polynomial_size();
    let cipher_modulus = lwe_outs[0].ciphertext_modulus();

    let mut equiv = GlweCiphertext::new(0, glwe_size, poly_size, cipher_modulus);
    let mut greater = equiv.clone();
    let mut less = equiv.clone();

    let mut equiv_xx0 = equiv.clone();
    let mut equiv_xx1 = equiv.clone();
    let mut equiv_x0 = equiv.clone();
    let mut equiv_x1 = equiv.clone();
    let mut equiv_0 = equiv.clone();
    let mut equiv_1 = equiv.clone();
    let mut mid_1 = equiv.clone();
    let mut mid_0 = equiv.clone();

    let encoded_msg_1 = 1_u64 << 60;
    let plaintext_list_1 = PlaintextList::new(encoded_msg_1, PlaintextCount(poly_size.0));
    let plaintext_list_0 = PlaintextList::new(0, PlaintextCount(poly_size.0));
    match op {
        ArithmeticOp::GT => {
            trivially_encrypt_glwe_ciphertext(&mut greater, &plaintext_list_1);
            trivially_encrypt_glwe_ciphertext(&mut equiv, &plaintext_list_0);
            trivially_encrypt_glwe_ciphertext(&mut less, &plaintext_list_0);
        }
        ArithmeticOp::GTE => {
            trivially_encrypt_glwe_ciphertext(&mut greater, &plaintext_list_1);
            trivially_encrypt_glwe_ciphertext(&mut equiv, &plaintext_list_1);
            trivially_encrypt_glwe_ciphertext(&mut less, &plaintext_list_0);
        }
        ArithmeticOp::LT => {
            trivially_encrypt_glwe_ciphertext(&mut greater, &plaintext_list_0);
            trivially_encrypt_glwe_ciphertext(&mut equiv, &plaintext_list_0);
            trivially_encrypt_glwe_ciphertext(&mut less, &plaintext_list_1);
        }
        ArithmeticOp::LTE => {
            trivially_encrypt_glwe_ciphertext(&mut greater, &plaintext_list_0);
            trivially_encrypt_glwe_ciphertext(&mut less, &plaintext_list_1);
            trivially_encrypt_glwe_ciphertext(&mut equiv, &plaintext_list_1);
        }
        ArithmeticOp::EQ => {
            trivially_encrypt_glwe_ciphertext(&mut greater, &plaintext_list_0);
            trivially_encrypt_glwe_ciphertext(&mut equiv, &plaintext_list_1);
            trivially_encrypt_glwe_ciphertext(&mut less, &plaintext_list_0);
        }
        _ => {}
    }

    let list_a = &input[0];
    let list_b = &input[1];
    let fft_viwe = fft.as_view();
    let mut buffer = ComputationBuffers::new();
    let buffer_size_req =
        cmux_assign_mem_optimized_requirement::<u64>(glwe_size, poly_size, fft_viwe)
            .unwrap()
            .unaligned_bytes_required();

    buffer.resize(buffer_size_req);

    for (index, (a, b)) in list_a
        .as_view()
        .into_ggsw_iter()
        .rev()
        .zip(list_b.as_view().into_ggsw_iter().rev())
        .enumerate()
    {
        match index % 4 {
            0 => {
                local_cmux(&less, &equiv, &b, &mut mid_1, &mut buffer, fft);
                local_cmux(&equiv, &greater, &b, &mut mid_0, &mut buffer, fft);
                local_cmux(&mid_0, &mid_1, &a, &mut equiv_xx1, &mut buffer, fft);

                local_cmux(&greater, &equiv, &b, &mut mid_1, &mut buffer, fft);
                local_cmux(&equiv, &less, &b, &mut mid_0, &mut buffer, fft);
                local_cmux(&mid_0, &mid_1, &a, &mut equiv_xx0, &mut buffer, fft);
            }
            1 => {
                local_cmux(&less, &equiv_xx1, &b, &mut mid_1, &mut buffer, fft);
                local_cmux(&equiv_xx0, &greater, &b, &mut mid_0, &mut buffer, fft);
                local_cmux(&mid_0, &mid_1, &a, &mut equiv_x1, &mut buffer, fft);

                local_cmux(&greater, &equiv_xx1, &b, &mut mid_1, &mut buffer, fft);
                local_cmux(&equiv_xx0, &less, &b, &mut mid_0, &mut buffer, fft);
                local_cmux(&mid_0, &mid_1, &a, &mut equiv_x0, &mut buffer, fft);
            }
            2 => {
                local_cmux(&less, &equiv_x1, &b, &mut mid_1, &mut buffer, fft);
                local_cmux(&equiv_x0, &greater, &b, &mut mid_0, &mut buffer, fft);
                local_cmux(&mid_0, &mid_1, &a, &mut equiv_1, &mut buffer, fft);

                local_cmux(&greater, &equiv_x1, &b, &mut mid_1, &mut buffer, fft);
                local_cmux(&equiv_x0, &less, &b, &mut mid_0, &mut buffer, fft);
                local_cmux(&mid_0, &mid_1, &a, &mut equiv_0, &mut buffer, fft);
            }

            3 => {
                local_cmux(&greater, &equiv_1, &b, &mut mid_1, &mut buffer, fft);
                local_cmux(&equiv_0, &less, &b, &mut mid_0, &mut buffer, fft);
                local_cmux(&mid_0, &mid_1, &a, &mut equiv, &mut buffer, fft);
            }
            _ => {
                // not used
            }
        }
    }
    for lwe in lwe_outs.iter_mut() {
        trivially_encrypt_lwe_ciphertext(lwe, Plaintext(0));
    }
    let result = lwe_outs.last_mut().unwrap();
    extract_lwe_sample_from_glwe_ciphertext(&equiv, result, MonomialDegree(0));
}

pub fn opmized_compare_cipherplain(
    input: &FourierGgswCiphertextList<Vec<c64>>,
    lwe_outs: &mut [LweCiphertext<Vec<u64>>],
    op: ArithmeticOp,
    immediate: usize,
    fft: &Fft,
) {
    let bits = input.count() * 4;
    let glwe_size = input.glwe_size();
    let poly_size = input.polynomial_size();
    let cipher_modulus = lwe_outs[0].ciphertext_modulus();

    let mut equiv = GlweCiphertext::new(0, glwe_size, poly_size, cipher_modulus);
    let mut greater = equiv.clone();
    let mut less = equiv.clone();

    let mut equiv_xx0 = equiv.clone();
    let mut equiv_xx1 = equiv.clone();
    let mut equiv_x0 = equiv.clone();
    let mut equiv_x1 = equiv.clone();
    let mut equiv_0 = equiv.clone();
    let mut equiv_1 = equiv.clone();
    let mut mid_1 = equiv.clone();
    let mut mid_0 = equiv.clone();

    let encoded_msg_1 = 1_u64 << 60;
    let plaintext_list_1 = PlaintextList::new(encoded_msg_1, PlaintextCount(poly_size.0));
    let plaintext_list_0 = PlaintextList::new(0, PlaintextCount(poly_size.0));
    match op {
        ArithmeticOp::GT => {
            trivially_encrypt_glwe_ciphertext(&mut greater, &plaintext_list_1);
            trivially_encrypt_glwe_ciphertext(&mut equiv, &plaintext_list_0);
            trivially_encrypt_glwe_ciphertext(&mut less, &plaintext_list_0);
        }
        ArithmeticOp::GTE => {
            trivially_encrypt_glwe_ciphertext(&mut greater, &plaintext_list_1);
            trivially_encrypt_glwe_ciphertext(&mut equiv, &plaintext_list_1);
            trivially_encrypt_glwe_ciphertext(&mut less, &plaintext_list_0);
        }
        ArithmeticOp::LT => {
            trivially_encrypt_glwe_ciphertext(&mut greater, &plaintext_list_0);
            trivially_encrypt_glwe_ciphertext(&mut equiv, &plaintext_list_0);
            trivially_encrypt_glwe_ciphertext(&mut less, &plaintext_list_1);
        }
        ArithmeticOp::LTE => {
            trivially_encrypt_glwe_ciphertext(&mut greater, &plaintext_list_0);
            trivially_encrypt_glwe_ciphertext(&mut less, &plaintext_list_1);
            trivially_encrypt_glwe_ciphertext(&mut equiv, &plaintext_list_1);
        }
        ArithmeticOp::EQ => {
            trivially_encrypt_glwe_ciphertext(&mut greater, &plaintext_list_0);
            trivially_encrypt_glwe_ciphertext(&mut equiv, &plaintext_list_1);
            trivially_encrypt_glwe_ciphertext(&mut less, &plaintext_list_0);
        }
        _ => {}
    }

    let plain_bits = encode_vec_nibbles(immediate, bits);

    let fft_viwe = fft.as_view();
    let mut buffer = ComputationBuffers::new();
    let buffer_size_req =
        cmux_assign_mem_optimized_requirement::<u64>(glwe_size, poly_size, fft_viwe)
            .unwrap()
            .unaligned_bytes_required();

    buffer.resize(buffer_size_req);

    for (index, (a, b)) in input
        .as_view()
        .into_ggsw_iter()
        .rev()
        .zip(plain_bits.iter().rev())
        .enumerate()
    {
        match index % 4 {
            0 => {
                plain_mux(&less, &equiv, b, &mut mid_1);
                plain_mux(&equiv, &greater, &b, &mut mid_0);
                local_cmux(&mid_0, &mid_1, &a, &mut equiv_xx1, &mut buffer, fft);

                plain_mux(&greater, &equiv, &b, &mut mid_1);
                plain_mux(&equiv, &less, &b, &mut mid_0);
                local_cmux(&mid_0, &mid_1, &a, &mut equiv_xx0, &mut buffer, fft);
            }
            1 => {
                plain_mux(&less, &equiv_xx1, &b, &mut mid_1);
                plain_mux(&equiv_xx0, &greater, &b, &mut mid_0);
                local_cmux(&mid_0, &mid_1, &a, &mut equiv_x1, &mut buffer, fft);

                plain_mux(&greater, &equiv_xx1, &b, &mut mid_1);
                plain_mux(&equiv_xx0, &less, &b, &mut mid_0);
                local_cmux(&mid_0, &mid_1, &a, &mut equiv_x0, &mut buffer, fft);
            }
            2 => {
                plain_mux(&less, &equiv_x1, &b, &mut mid_1);
                plain_mux(&equiv_x0, &greater, &b, &mut mid_0);
                local_cmux(&mid_0, &mid_1, &a, &mut equiv_1, &mut buffer, fft);

                plain_mux(&greater, &equiv_x1, &b, &mut mid_1);
                plain_mux(&equiv_x0, &less, &b, &mut mid_0);
                local_cmux(&mid_0, &mid_1, &a, &mut equiv_0, &mut buffer, fft);
            }

            3 => {
                plain_mux(&greater, &equiv_1, &b, &mut mid_1);
                plain_mux(&equiv_0, &less, &b, &mut mid_0);
                local_cmux(&mid_0, &mid_1, &a, &mut equiv, &mut buffer, fft);
            }
            _ => {
                // not used
            }
        }
    }
    for lwe in lwe_outs.iter_mut() {
        trivially_encrypt_lwe_ciphertext(lwe, Plaintext(0));
    }
    let result = lwe_outs.last_mut().unwrap();
    extract_lwe_sample_from_glwe_ciphertext(&equiv, result, MonomialDegree(0));
}

pub fn opmized_compare_plaincipher(
    input: &FourierGgswCiphertextList<Vec<c64>>,
    lwe_outs: &mut [LweCiphertext<Vec<u64>>],
    op: ArithmeticOp,
    immediate: usize,
    fft: &Fft,
) {
    let glwe_size = input.glwe_size();
    let poly_size = input.polynomial_size();
    let cipher_modulus = lwe_outs[0].ciphertext_modulus();

    let mut equiv = GlweCiphertext::new(0, glwe_size, poly_size, cipher_modulus);
    let mut greater = equiv.clone();
    let mut less = equiv.clone();

    let mut equiv_xx0 = equiv.clone();
    let mut equiv_xx1 = equiv.clone();
    let mut equiv_x0 = equiv.clone();
    let mut equiv_x1 = equiv.clone();
    let mut equiv_0 = equiv.clone();
    let mut equiv_1 = equiv.clone();
    let mut mid_1 = equiv.clone();
    let mut mid_0 = equiv.clone();

    let encoded_msg_1 = 1_u64 << 60;
    let plaintext_list_1 = PlaintextList::new(encoded_msg_1, PlaintextCount(poly_size.0));
    let plaintext_list_0 = PlaintextList::new(0, PlaintextCount(poly_size.0));
    let bits = input.count() * 4;
    let plain_bits = encode_vec_nibbles(immediate, bits);
    match op {
        ArithmeticOp::GT => {
            trivially_encrypt_glwe_ciphertext(&mut greater, &plaintext_list_1);
            trivially_encrypt_glwe_ciphertext(&mut equiv, &plaintext_list_0);
            trivially_encrypt_glwe_ciphertext(&mut less, &plaintext_list_0);
        }
        ArithmeticOp::GTE => {
            trivially_encrypt_glwe_ciphertext(&mut greater, &plaintext_list_1);
            trivially_encrypt_glwe_ciphertext(&mut equiv, &plaintext_list_1);
            trivially_encrypt_glwe_ciphertext(&mut less, &plaintext_list_0);
        }
        ArithmeticOp::LT => {
            trivially_encrypt_glwe_ciphertext(&mut greater, &plaintext_list_0);
            trivially_encrypt_glwe_ciphertext(&mut equiv, &plaintext_list_0);
            trivially_encrypt_glwe_ciphertext(&mut less, &plaintext_list_1);
        }
        ArithmeticOp::LTE => {
            trivially_encrypt_glwe_ciphertext(&mut greater, &plaintext_list_0);
            trivially_encrypt_glwe_ciphertext(&mut less, &plaintext_list_1);
            trivially_encrypt_glwe_ciphertext(&mut equiv, &plaintext_list_1);
        }
        ArithmeticOp::EQ => {
            trivially_encrypt_glwe_ciphertext(&mut greater, &plaintext_list_0);
            trivially_encrypt_glwe_ciphertext(&mut equiv, &plaintext_list_1);
            trivially_encrypt_glwe_ciphertext(&mut less, &plaintext_list_0);
        }
        _ => {}
    }

    let fft_viwe = fft.as_view();
    let mut buffer = ComputationBuffers::new();
    let buffer_size_req =
        cmux_assign_mem_optimized_requirement::<u64>(glwe_size, poly_size, fft_viwe)
            .unwrap()
            .unaligned_bytes_required();

    buffer.resize(buffer_size_req);

    for (index, (a, b)) in plain_bits
        .iter()
        .rev()
        .zip(input.as_view().into_ggsw_iter().rev())
        .enumerate()
    {
        match index % 4 {
            0 => {
                local_cmux(&less, &equiv, &b, &mut mid_1, &mut buffer, fft);
                local_cmux(&equiv, &greater, &b, &mut mid_0, &mut buffer, fft);
                plain_mux(&mid_0, &mid_1, &a, &mut equiv_xx1);

                local_cmux(&greater, &equiv, &b, &mut mid_1, &mut buffer, fft);
                local_cmux(&equiv, &less, &b, &mut mid_0, &mut buffer, fft);
                plain_mux(&mid_0, &mid_1, &a, &mut equiv_xx0);
            }
            1 => {
                local_cmux(&less, &equiv_xx1, &b, &mut mid_1, &mut buffer, fft);
                local_cmux(&equiv_xx0, &greater, &b, &mut mid_0, &mut buffer, fft);
                plain_mux(&mid_0, &mid_1, &a, &mut equiv_x1);

                local_cmux(&greater, &equiv_xx1, &b, &mut mid_1, &mut buffer, fft);
                local_cmux(&equiv_xx0, &less, &b, &mut mid_0, &mut buffer, fft);
                plain_mux(&mid_0, &mid_1, &a, &mut equiv_x0);
            }
            2 => {
                local_cmux(&less, &equiv_x1, &b, &mut mid_1, &mut buffer, fft);
                local_cmux(&equiv_x0, &greater, &b, &mut mid_0, &mut buffer, fft);
                plain_mux(&mid_0, &mid_1, &a, &mut equiv_1);

                local_cmux(&greater, &equiv_x1, &b, &mut mid_1, &mut buffer, fft);
                local_cmux(&equiv_x0, &less, &b, &mut mid_0, &mut buffer, fft);
                plain_mux(&mid_0, &mid_1, &a, &mut equiv_0);
            }

            3 => {
                local_cmux(&greater, &equiv_1, &b, &mut mid_1, &mut buffer, fft);
                local_cmux(&equiv_0, &less, &b, &mut mid_0, &mut buffer, fft);
                plain_mux(&mid_0, &mid_1, &a, &mut equiv);
            }
            _ => {
                // not used
            }
        }
    }
    for lwe in lwe_outs.iter_mut() {
        trivially_encrypt_lwe_ciphertext(lwe, Plaintext(0));
    }
    let result = lwe_outs.last_mut().unwrap();
    extract_lwe_sample_from_glwe_ciphertext(&equiv, result, MonomialDegree(0));
}
fn local_cmux(
    input_0: &GlweCiphertext<Vec<u64>>,
    input_1: &GlweCiphertext<Vec<u64>>,
    control: &FourierGgswCiphertext<&[c64]>,
    mut output: &mut GlweCiphertext<Vec<u64>>,
    buffer: &mut ComputationBuffers,
    fft: &Fft,
) {
    let mut temp = input_1.clone();
    output.clone_from(input_0);
    let stack = buffer.stack();
    let fft_view = fft.as_view();
    cmux_assign_mem_optimized(&mut output, &mut temp, control, fft_view, stack);
}

fn plain_mux(
    input_0: &GlweCiphertext<Vec<u64>>,
    input_1: &GlweCiphertext<Vec<u64>>,
    control: &usize,
    output: &mut GlweCiphertext<Vec<u64>>,
) {
    match control {
        0 => {
            output.clone_from(input_0);
        }
        1 => {
            output.clone_from(input_1);
        }
        _ => {
            unreachable!();
        }
    }
}

fn encode_vec_nibbles(input: usize, length: usize) -> Vec<usize> {
    debug_assert!(length % 4 == 0, "length must be a multiple of 4");
    debug_assert!(length <= usize::BITS as usize, "length too large for usize");

    // 1) 取出低 length 位（高位在前） -> bits
    let mut bits = Vec::with_capacity(length);
    for i in (0..length).rev() {
        bits.push(((input >> i) & 1) as usize);
    }

    // 2) 每 4 位一组做前缀异或 -> ec
    let mut vec = vec![0usize; length];
    for base in (0..length).step_by(4) {
        let mut acc = 0usize;
        for j in 0..4 {
            acc ^= bits[base + j];
            vec[base + j] = acc;
        }
    }

    vec
}
