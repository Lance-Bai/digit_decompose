use crate::operations::{
    cipher_lut::generate_lut_from_vecs_auto,
    operand::ArithmeticOp,
    plain_lut::{
        build_split_lut_tables, build_split_lut_tables_cipher_plain,
        build_split_lut_tables_plain_cipher,
    },
};
use aligned_vec::CACHELINE_ALIGN;
use concrete_fft::c64;
use dyn_stack::{PodStack, ReborrowMut};
use rayon::{
    iter::{IndexedParallelIterator, IntoParallelRefIterator, ParallelIterator},
    slice::ParallelSliceMut,
};
use tfhe::core_crypto::fft_impl::fft64::math::fft::FftView;
use tfhe::core_crypto::prelude::{
    ComputationBuffers, Fft, FourierGgswCiphertextList, LweCiphertext, PolynomialList,
};
use tfhe::core_crypto::{
    fft_impl::fft64::crypto::wop_pbs::{
        blind_rotate_assign, cmux_tree_memory_optimized, vertical_packing_scratch,
    },
    prelude::*,
};

#[derive(Debug, Clone, Copy)]
pub enum OperandType {
    BothCipher,
    PlainCipher,
    CipherPlain,
}

pub struct Operation {
    // 操作类型和参数配置
    pub op: ArithmeticOp,
    pub op_type: OperandType,
    pub bit_width: usize,  //8,16,32
    pub chunk_size: usize, // 1,2,4
    // 只存密文查找表
    pub cipher_lut: Vec<PolynomialList<Vec<u64>>>,
    pub lut_pack_size: usize, // 每个多项式能打包多少张表
    pub immediate: Option<usize>,
}

impl Operation {
    pub fn new(
        op: ArithmeticOp,
        op_type: OperandType,
        bit_width: usize,
        chunk_size: usize,
        poly_size: tfhe::boolean::prelude::PolynomialSize,
        delta: u64,
        immediate: Option<usize>,
    ) -> Self {
        if matches!(
            op,
            ArithmeticOp::MOVE | ArithmeticOp::CSEL | ArithmeticOp::SIGN
        ) {
            Self {
                op,
                op_type,
                bit_width,
                chunk_size,
                cipher_lut: Vec::new(), // 没有查找表
                lut_pack_size: 0,
                immediate,
            }
        } else if matches!(
            op,
            ArithmeticOp::GT
                | ArithmeticOp::GTE
                | ArithmeticOp::LT
                | ArithmeticOp::LTE
                | ArithmeticOp::EQ
        ) && bit_width >= 16
        {
            Self {
                op,
                op_type,
                bit_width,
                chunk_size,
                cipher_lut: Vec::new(), // opmised compare 操作没有查找表
                lut_pack_size: 0,
                immediate,
            }
        } else {
            let plain_lut = match op_type {
                OperandType::BothCipher => {
                    build_split_lut_tables(bit_width, vec![bit_width, bit_width], chunk_size, &op)
                }
                OperandType::PlainCipher => build_split_lut_tables_plain_cipher(
                    bit_width,
                    immediate.unwrap(),
                    vec![bit_width],
                    chunk_size,
                    &op,
                ),
                OperandType::CipherPlain => build_split_lut_tables_cipher_plain(
                    bit_width,
                    immediate.unwrap(),
                    vec![bit_width],
                    chunk_size,
                    &op,
                ),
            };

            let (cipher_lut, lut_pack_size) =
                generate_lut_from_vecs_auto(&plain_lut, poly_size, delta);
            Self {
                op,
                op_type,
                bit_width,
                chunk_size,
                cipher_lut,
                lut_pack_size,
                immediate,
            }
        }
    }

    pub fn parallel_vertical_packing_multi_lookup(
        &self,
        lwe_outs: &mut [LweCiphertext<Vec<u64>>],
        ggsw_list: &FourierGgswCiphertextList<Vec<c64>>,
        fft: &Fft,
    ) {
        let lut_input_size = match self.op_type {
            OperandType::BothCipher => self.bit_width * 2,
            OperandType::PlainCipher | OperandType::CipherPlain => self.bit_width,
        };
        let ggsw_view = ggsw_list.as_view();
        let fft_view = fft.as_view();

        let group_size = self.lut_pack_size.min(self.bit_width / self.chunk_size);
        let lut_size = 1_usize << lut_input_size;

        self.cipher_lut
            .par_iter()
            .zip(lwe_outs.par_chunks_mut(group_size))
            .for_each(|(lut, lwe_group)| {
                let mut local_buffer = ComputationBuffers::new();
                let need = vertical_packing_scratch::<u64>(
                    ggsw_view.glwe_size(),
                    ggsw_view.polynomial_size(),
                    lut.polynomial_count(),
                    ggsw_view.count(),
                    fft_view,
                )
                .unwrap()
                .unaligned_bytes_required();
                local_buffer.resize(need);

                let stack = local_buffer.stack();
                let temp = horizontal_vertical_packing_without_extract(
                    lut.as_view(),
                    ggsw_view,
                    fft_view,
                    stack,
                    lwe_group[0].ciphertext_modulus(),
                );
                for (i, lwe) in lwe_group.iter_mut().enumerate() {
                    extract_lwe_sample_from_glwe_ciphertext(
                        &temp,
                        lwe,
                        MonomialDegree(i * lut_size),
                    );
                }
            });
    }


    pub fn vertical_packing_multi_lookup(
        &self,
        lwe_outs: &mut [LweCiphertext<Vec<u64>>],
        ggsw_list: &FourierGgswCiphertextList<Vec<c64>>,
        fft: &Fft,
        buffer: &mut ComputationBuffers,
    ) {
        let lut_input_size = match self.op_type {
            OperandType::BothCipher => self.bit_width * 2,
            OperandType::PlainCipher => self.bit_width,
            OperandType::CipherPlain => self.bit_width,
        };
        assert_eq!(
            lut_input_size,
            ggsw_list.count(),
            "lut_input_size = {}, ggsw_list.count()={}",
            lut_input_size,
            ggsw_list.count()
        );
        let lut = &self.cipher_lut[0];
        buffer.resize(
            vertical_packing_scratch::<u64>(
                ggsw_list.glwe_size(),
                ggsw_list.polynomial_size(),
                lut.polynomial_count(),
                ggsw_list.count(),
                fft.as_view(),
            )
            .unwrap()
            .unaligned_bytes_required(),
        );

        let lut_pack_size = self.lut_pack_size;
        let lut_size = 1_usize << lut_input_size;
        let lut_num = self.bit_width / self.chunk_size;
        for (lut, lwe_out) in self
            .cipher_lut
            .iter()
            .zip(lwe_outs.into_chunks(lut_pack_size.min(lut_num)))
        {
            let stack = buffer.stack();
            let temp = horizontal_vertical_packing_without_extract(
                lut.as_view(),
                ggsw_list.as_view(),
                fft.as_view(),
                stack,
                lwe_out[0].ciphertext_modulus(),
            );
            for (i, lwe) in lwe_out.iter_mut().enumerate() {
                extract_lwe_sample_from_glwe_ciphertext(&temp, lwe, MonomialDegree(i * lut_size));
            }
        }
    }
}

pub fn horizontal_vertical_packing_without_extract<Scalar: UnsignedTorus + CastInto<usize>>(
    lut: PolynomialList<&[Scalar]>,
    ggsw_list: FourierGgswCiphertextList<&[c64]>,
    fft: FftView<'_>,
    stack: PodStack<'_>,
    ciphertext_modulus: CiphertextModulus<Scalar>,
) -> GlweCiphertext<Vec<Scalar>> {
    let polynomial_size = ggsw_list.polynomial_size();
    let glwe_size = ggsw_list.glwe_size();

    // Get the base 2 logarithm (rounded down) of the number of polynomials in the list i.e. if
    // there is one polynomial, the number will be 0
    let log_lut_number: usize =
        Scalar::BITS - 1 - lut.polynomial_count().0.leading_zeros() as usize;

    let log_number_of_luts_for_cmux_tree = if log_lut_number > ggsw_list.count() {
        // this means that we dont have enough GGSW to perform the CMux tree, we can only do the
        // Blind rotation
        0
    } else {
        log_lut_number
    };

    // split the vec of GGSW in two, the msb GGSW is for the CMux tree and the lsb GGSW is for
    // the last blind rotation.
    let (cmux_ggsw, br_ggsw) = ggsw_list.split_at(log_number_of_luts_for_cmux_tree);

    let (mut cmux_tree_lut_res_data, mut stack) =
        stack.make_aligned_with(polynomial_size.0 * glwe_size.0, CACHELINE_ALIGN, |_| {
            Scalar::ZERO
        });
    let mut cmux_tree_lut_res = GlweCiphertext::from_container(
        &mut *cmux_tree_lut_res_data,
        polynomial_size,
        ciphertext_modulus,
    );

    cmux_tree_memory_optimized(
        cmux_tree_lut_res.as_mut_view(),
        lut,
        cmux_ggsw,
        fft,
        stack.rb_mut(),
    );
    blind_rotate_assign(
        cmux_tree_lut_res.as_mut_view(),
        br_ggsw,
        fft,
        stack.rb_mut(),
    );

    // sample extract of the RLWE of the Vertical packing

    GlweCiphertext::from_container(
        cmux_tree_lut_res.as_ref().to_vec(),
        polynomial_size,
        ciphertext_modulus,
    )
}
