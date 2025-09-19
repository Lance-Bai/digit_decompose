use std::collections::HashMap;

use aligned_vec::ABox;
use concrete_fft::c64;
use rayon::prelude::*;
use refined_tfhe_lhe::{gen_all_auto_keys, generate_scheme_switching_key, AutomorphKey};
use tfhe::core_crypto::{
    prelude::{
        allocate_and_encrypt_new_lwe_ciphertext, allocate_and_generate_new_binary_glwe_secret_key,
        allocate_and_generate_new_lwe_bootstrap_key, convert_standard_lwe_bootstrap_key_to_fourier,
        decrypt_lwe_ciphertext, encrypt_lwe_ciphertext, ActivatedRandomGenerator,
        EncryptionRandomGenerator, Fft, FourierGgswCiphertextList, FourierLweBootstrapKey,
        FourierLweBootstrapKeyOwned, GlweSecretKeyOwned, LweCiphertext, LweSecretKeyOwned,
        Plaintext, SecretRandomGenerator,
    },
    seeders::{new_seeder, Seeder},
};

use crate::{
    operations::{
        operand::ArithmeticOp,
        operation::{OperandType, Operation},
    },
    opmized_operations::{
        compare::{
            opmized_compare_bothcipher, opmized_compare_cipherplain, opmized_compare_plaincipher,
        },
        sign::sign,
    },
    processors::{
        cbs_4_bits::circuit_bootstrapping_4_bits_at_once_rev_tr,
        key_gen::allocate_and_generate_new_reused_lwe_key,
        lwe_stored_ksk::{
            allocate_and_generate_new_stored_reused_lwe_keyswitch_key, LweStoredReusedKeyswitchKey,
        },
    },
    utils::parms::ProcessorParam,
};

pub struct Step {
    pub op_index: usize,           // Operation index in Vec
    pub input_indices: Vec<usize>, // Oparnd index(s) in Vec
    pub output_index: usize,       // result inedx in Vec
}

impl Step {
    pub fn new(op_index: usize, input_indices: Vec<usize>, output_index: usize) -> Self {
        Self {
            op_index,
            input_indices,
            output_index,
        }
    }
}

pub struct OperationManager {
    pub operations: Vec<Operation>,
    pub execution_plan: Vec<Step>,
    pub fft: Fft,
    pub boxed_seeder: Box<dyn Seeder>,
    pub secret_generator: SecretRandomGenerator<ActivatedRandomGenerator>,
    pub encryption_generator: EncryptionRandomGenerator<ActivatedRandomGenerator>,

    pub params: ProcessorParam<u64>,
    pub glwe_sk: GlweSecretKeyOwned<u64>,
    pub lwe_sk_after_ks: LweSecretKeyOwned<u64>,
    pub ksk: LweStoredReusedKeyswitchKey<Vec<u64>>,
    pub fourier_bsk: FourierLweBootstrapKeyOwned,
    pub auto_keys: HashMap<usize, AutomorphKey<ABox<[c64]>>>,
    pub ss_key: FourierGgswCiphertextList<Vec<c64>>,

    pub ggsw_lists: Vec<FourierGgswCiphertextList<Vec<c64>>>,
    pub lwe_lists: Vec<Vec<LweCiphertext<Vec<u64>>>>,
    pub data_len: usize,
}

impl OperationManager {
    pub fn new(param: ProcessorParam<u64>, mem_size: usize, data_len: usize) -> Self {
        let lwe_dimension = param.lwe_dimension();
        let lwe_modular_std_dev = param.lwe_modular_std_dev();
        let polynomial_size = param.polynomial_size();
        let glwe_dimension = param.glwe_dimension();
        let glwe_modular_std_dev = param.glwe_modular_std_dev();
        let pbs_base_log = param.pbs_base_log();
        let pbs_level = param.pbs_level();
        let ks_base_log = param.ks_base_log();
        let ks_level = param.ks_level();
        let auto_base_log = param.auto_base_log();
        let auto_level = param.auto_level();
        let auto_fft_type = param.fft_type_auto();
        let ss_base_log = param.ss_base_log();
        let ss_level = param.ss_level();
        let cbs_base_log = param.cbs_base_log();
        let cbs_level = param.cbs_level();
        let ciphertext_modulus = param.ciphertext_modulus();
        let message_size = param.message_size();
        let extract_size = param.extract_size();
        let glwe_size = glwe_dimension.to_glwe_size();

        let mut boxed_seeder = new_seeder();
        let seeder = boxed_seeder.as_mut();

        let mut secret_generator = SecretRandomGenerator::new(seeder.seed());
        let mut encryption_generator = EncryptionRandomGenerator::new(seeder.seed(), seeder);

        // Generate keys
        let glwe_sk = allocate_and_generate_new_binary_glwe_secret_key(
            glwe_dimension,
            polynomial_size,
            &mut secret_generator,
        );
        let glwe_lwe_sk = glwe_sk.as_lwe_secret_key();
        let lwe_sk_after_ks = allocate_and_generate_new_reused_lwe_key(&glwe_lwe_sk, lwe_dimension);
        let ksk = allocate_and_generate_new_stored_reused_lwe_keyswitch_key(
            &glwe_lwe_sk,
            &lwe_sk_after_ks,
            ks_base_log,
            ks_level,
            glwe_modular_std_dev,
            ciphertext_modulus,
            &mut encryption_generator,
        );

        let bsk = allocate_and_generate_new_lwe_bootstrap_key(
            &lwe_sk_after_ks,
            &glwe_sk,
            pbs_base_log,
            pbs_level,
            glwe_modular_std_dev,
            ciphertext_modulus,
            &mut encryption_generator,
        );

        let mut fourier_bsk = FourierLweBootstrapKey::new(
            bsk.input_lwe_dimension(),
            bsk.glwe_size(),
            bsk.polynomial_size(),
            bsk.decomposition_base_log(),
            bsk.decomposition_level_count(),
        );
        convert_standard_lwe_bootstrap_key_to_fourier(&bsk, &mut fourier_bsk);
        drop(bsk);

        let auto_keys = gen_all_auto_keys(
            auto_base_log,
            auto_level,
            auto_fft_type,
            &glwe_sk,
            glwe_modular_std_dev,
            &mut encryption_generator,
        );

        let ss_key_owned = generate_scheme_switching_key(
            &glwe_sk,
            ss_base_log,
            ss_level,
            glwe_modular_std_dev,
            ciphertext_modulus,
            &mut encryption_generator,
        );

        let fourier_ggsw_list = FourierGgswCiphertextList::new(
            vec![
                c64::default();
                extract_size
                    * polynomial_size.to_fourier_polynomial_size().0
                    * glwe_size.0
                    * glwe_size.0
                    * cbs_level.0
            ],
            extract_size,
            glwe_size,
            polynomial_size,
            cbs_base_log,
            cbs_level,
        );
        let fourier_ggsw_lists = vec![fourier_ggsw_list; data_len.div_ceil(message_size) * 2];

        let lwe = allocate_and_encrypt_new_lwe_ciphertext(
            &glwe_lwe_sk,
            Plaintext(0),
            lwe_modular_std_dev,
            ciphertext_modulus,
            &mut encryption_generator,
        );

        let lwe_list = vec![lwe; data_len.div_ceil(message_size)];
        let lwe_lists = vec![lwe_list; mem_size];

        Self {
            params: param,
            operations: Vec::new(),
            execution_plan: Vec::new(),
            fft: Fft::new(polynomial_size),
            boxed_seeder,
            secret_generator,
            encryption_generator,
            glwe_sk,
            lwe_sk_after_ks,
            ksk,
            fourier_bsk,
            auto_keys,
            ss_key: ss_key_owned,
            ggsw_lists: fourier_ggsw_lists,
            lwe_lists,
            data_len,
        }
    }

    pub fn add_operation(
        &mut self,
        op: ArithmeticOp,
        op_type: OperandType,
        immediate: Option<usize>,
    ) {
        let operand = Operation::new(
            op,
            op_type,
            self.data_len,
            self.params.extract_size(),
            self.params.polynomial_size(),
            1 << (u64::BITS as usize - self.params.message_size()),
            immediate,
        );
        self.operations.push(operand);
    }

    pub fn add_operatoins(&mut self, ops: Vec<(ArithmeticOp, OperandType, Option<usize>)>) {
        for (op, op_type, immediate) in ops {
            self.add_operation(op, op_type, immediate);
        }
    }

    pub fn remove_operation(&mut self, index: usize) {
        self.operations.remove(index);
    }

    pub fn set_execution_plan(&mut self, plan: Vec<Step>) {
        self.execution_plan = plan;
    }

    pub fn load_data(&mut self, data: usize, index: usize) {
        assert!(index < self.lwe_lists.len(), "Index out of bounds");

        // map_chunks_to_lwe return Vec<(&mut LweCiphertext<Vec<u64>>, u64)>
        let mapping = map_chunks_to_lwe_mut(
            &mut self.lwe_lists,
            index,
            data,
            self.data_len,
            self.params.message_size(),
        );

        for (lwe, chunk) in mapping {
            encrypt_lwe_ciphertext(
                &self.glwe_sk.as_lwe_secret_key(),
                lwe,
                Plaintext(chunk << (u64::BITS as usize - self.params.message_size())),
                self.params.glwe_modular_std_dev(),
                &mut self.encryption_generator,
            );
        }
    }

    pub fn get_data(&mut self, index: usize) -> usize {
        let lwe_list = self.lwe_lists.get(index).expect("Index out of bounds");
        let mut chunks = vec![0_u64; self.data_len.div_ceil(self.params.message_size())];

        for (lwe, chunk) in lwe_list.iter().zip(chunks.iter_mut()) {
            let plain = decrypt_lwe_ciphertext(&self.glwe_sk.as_lwe_secret_key(), lwe);
            *chunk = (((plain.0 >> (u64::BITS as usize - self.params.message_size() - 1)) + 1)
                >> 1)
                % (1 << self.params.message_size());
        }

        let mut result: usize = 0;
        for &chunk in &chunks {
            result = (result << self.params.message_size()) | (chunk as usize);
        }

        result
    }

    /// execute the whole pipline
    pub fn execute(&mut self) {
        for step in &self.execution_plan {
            let op = &self.operations[step.op_index];
            let is_both_cipher = match op.op_type {
                OperandType::BothCipher => true,
                _ => false,
            };
            match (op.op, op.bit_width) {
                (ArithmeticOp::CSEL, _) => {}
                (ArithmeticOp::SIGN, _) => {
                    let fourier_bsk_view = self.fourier_bsk.as_view();
                    let auto_keys = &self.auto_keys;
                    let ss_key_view = self.ss_key.as_view();
                    let ksk = &self.ksk;
                    let params = &self.params;

                    let lwe0 = self.lwe_lists[step.input_indices[0]].as_slice();
                    let lwe1_opt = match op.op_type {
                        OperandType::BothCipher => {
                            Some(self.lwe_lists[step.input_indices[1]].as_slice())
                        }
                        _ => None,
                    };

                    let mut ggsw_lists = std::mem::take(&mut self.ggsw_lists);

                    let total_lwe = lwe0.len() + lwe1_opt.map_or(0, |s| s.len());

                    ggsw_lists
                        .par_iter_mut()
                        .enumerate()
                        .take(total_lwe)
                        .for_each(|(i, ggsw)| {
                            let lwe = if i < lwe0.len() {
                                &lwe0[i]
                            } else {
                                &lwe1_opt.unwrap()[i - lwe0.len()]
                            };

                            circuit_bootstrapping_4_bits_at_once_rev_tr(
                                lwe,
                                ggsw,
                                fourier_bsk_view,
                                auto_keys,
                                ss_key_view,
                                ksk,
                                params,
                            );
                        });

                    self.ggsw_lists = ggsw_lists;
                    let temp = self.ggsw_lists.clone();
                    let input = concat_ggsw_lists(temp, false);
                    sign(
                        &input,
                        self.lwe_lists[step.output_index].as_mut_slice(),
                        op.immediate.unwrap(),
                        &self.fft,
                    );
                }
                (ArithmeticOp::MOVE, _) => {
                    let temp = self.lwe_lists[step.input_indices[0]].clone();
                    for (input, output) in temp
                        .iter()
                        .zip(self.lwe_lists[step.output_index].iter_mut())
                    {
                        output.clone_from(input);
                    }
                    continue;
                }

                (x, y)
                    if matches!(
                        x,
                        ArithmeticOp::GT
                            | ArithmeticOp::GTE
                            | ArithmeticOp::LT
                            | ArithmeticOp::LTE
                            | ArithmeticOp::EQ
                    ) && y >= 16 =>
                {
                    let fourier_bsk_view = self.fourier_bsk.as_view();
                    let auto_keys = &self.auto_keys;
                    let ss_key_view = self.ss_key.as_view();
                    let ksk = &self.ksk;
                    let params = &self.params;

                    let lwe0 = self.lwe_lists[step.input_indices[0]].as_slice();
                    let lwe1_opt = match op.op_type {
                        OperandType::BothCipher => {
                            Some(self.lwe_lists[step.input_indices[1]].as_slice())
                        }
                        _ => None,
                    };

                    let mut ggsw_lists = std::mem::take(&mut self.ggsw_lists);

                    let total_lwe = lwe0.len() + lwe1_opt.map_or(0, |s| s.len());
                    ggsw_lists
                        .par_iter_mut()
                        .enumerate()
                        .take(total_lwe)
                        .for_each(|(i, ggsw)| {
                            let lwe = if i < lwe0.len() {
                                &lwe0[i]
                            } else {
                                &lwe1_opt.unwrap()[i - lwe0.len()]
                            };
                            circuit_bootstrapping_4_bits_at_once_rev_tr(
                                lwe,
                                ggsw,
                                fourier_bsk_view,
                                auto_keys,
                                ss_key_view,
                                ksk,
                                params,
                            );
                        });

                    self.ggsw_lists = ggsw_lists;
                    let temp = self.ggsw_lists.clone();
                    match op.op_type {
                        OperandType::BothCipher => {
                            let (temp0, temp1) = temp.split_at(self.ggsw_lists.len() / 2);
                            let input0 = concat_ggsw_lists(temp0.to_vec(), true);
                            let input1 = concat_ggsw_lists(temp1.to_vec(), true);
                            let input = vec![input0, input1];

                            opmized_compare_bothcipher(
                                &input,
                                self.lwe_lists[step.output_index].as_mut_slice(),
                                op.op,
                                &self.fft,
                            );
                        }
                        OperandType::CipherPlain => {
                            let input = concat_ggsw_lists(temp, false);
                            opmized_compare_cipherplain(
                                &input,
                                self.lwe_lists[step.output_index].as_mut_slice(),
                                op.op,
                                op.immediate.unwrap(),
                                &self.fft,
                            );
                        }
                        OperandType::PlainCipher => {
                            let input = concat_ggsw_lists(temp, false);
                            opmized_compare_plaincipher(
                                &input,
                                self.lwe_lists[step.output_index].as_mut_slice(),
                                op.op,
                                op.immediate.unwrap(),
                                &self.fft,
                            );
                        }
                    }
                }

                _ => {
                    let fourier_bsk_view = self.fourier_bsk.as_view();
                    let auto_keys = &self.auto_keys;
                    let ss_key_view = self.ss_key.as_view();
                    let ksk = &self.ksk;
                    let params = &self.params;
                    let lwe0 = self.lwe_lists[step.input_indices[0]].as_slice();
                    let lwe1_opt = match op.op_type {
                        OperandType::BothCipher => {
                            Some(self.lwe_lists[step.input_indices[1]].as_slice())
                        }
                        _ => None,
                    };
                    let mut ggsw_lists = std::mem::take(&mut self.ggsw_lists);

                    let total_lwe = lwe0.len() + lwe1_opt.map_or(0, |s| s.len());
                    ggsw_lists
                        .par_iter_mut()
                        .enumerate()
                        .take(total_lwe)
                        .for_each(|(i, ggsw)| {
                            let lwe = if i < lwe0.len() {
                                &lwe0[i]
                            } else {
                                &lwe1_opt.unwrap()[i - lwe0.len()]
                            };

                            circuit_bootstrapping_4_bits_at_once_rev_tr(
                                lwe,
                                ggsw,
                                fourier_bsk_view,
                                auto_keys,
                                ss_key_view,
                                ksk,
                                params,
                            );
                        });

                    let temp_ggsw_lists = ggsw_lists.clone();
                    self.ggsw_lists = ggsw_lists;

                    let input_bits = concat_ggsw_lists(temp_ggsw_lists, is_both_cipher);

                    op.parallel_vertical_packing_multi_lookup(
                        self.lwe_lists[step.output_index].as_mut_slice(),
                        &input_bits,
                        &self.fft,
                    );
                }
            }
        }
    }
}

pub fn concat_ggsw_lists(
    lists: Vec<FourierGgswCiphertextList<Vec<c64>>>,
    is_both_cipher: bool,
) -> FourierGgswCiphertextList<Vec<c64>> {
    assert!(!lists.is_empty(), "GGSW lis can not be empty");

    let glwe_size = lists[0].glwe_size();
    let decomposition_level_count = lists[0].decomposition_level_count();
    let decomposition_base_log = lists[0].decomposition_base_log();
    let poly_size = lists[0].polynomial_size();

    let mut all_data = Vec::new();
    let mut total_count = 0;

    if is_both_cipher {
        for list in lists {
            total_count += list.count();
            all_data.extend_from_slice(&list.data());
        }
    } else {
        let half = lists.len() / 2;
        for list in lists.into_iter().take(half) {
            total_count += list.count();
            all_data.extend_from_slice(&list.data());
        }
    }

    FourierGgswCiphertextList::new(
        all_data,
        total_count,
        glwe_size,
        poly_size,
        decomposition_base_log,
        decomposition_level_count,
    )
}

pub fn split_bits_high_to_low(value: usize, data_len: usize, message_size: usize) -> Vec<u64> {
    assert!(message_size > 0, "message_size must > 0");
    assert!(data_len > 0, "data_len must > 0");
    assert!(
        data_len <= usize::BITS as usize,
        "data_len over usize width"
    );

    let mask = (1usize << data_len) - 1;
    let val = value & mask;

    let num_chunks = (data_len + message_size - 1) / message_size;
    let mut chunks = Vec::with_capacity(num_chunks);

    for i in (0..num_chunks).rev() {
        let shift = i * message_size;
        let chunk_val = ((val >> shift) & ((1 << message_size) - 1)) as u64;
        chunks.push(chunk_val);
    }

    chunks
}

pub fn map_chunks_to_lwe<'a>(
    lwe_lists: &'a Vec<Vec<LweCiphertext<Vec<u64>>>>,
    list_index: usize,
    value: usize,
    data_len: usize,
    message_size: usize,
) -> Vec<(&'a LweCiphertext<Vec<u64>>, u64)> {
    let chunks = split_bits_high_to_low(value, data_len, message_size);

    let lwe_vec = lwe_lists.get(list_index).expect("list_index overflow");

    assert_eq!(lwe_vec.len(), chunks.len(), "LWE number blocks miss match");
    lwe_vec.iter().zip(chunks.into_iter()).collect()
}

pub fn map_chunks_to_lwe_mut<'a>(
    lwe_lists: &'a mut Vec<Vec<LweCiphertext<Vec<u64>>>>,
    list_index: usize,
    value: usize,
    message_size: usize,
    extract_size: usize,
) -> Vec<(&'a mut LweCiphertext<Vec<u64>>, u64)> {
    let chunks = split_bits_high_to_low(value, message_size, extract_size);

    let lwe_vec = lwe_lists.get_mut(list_index).expect("list_index overflow");

    assert_eq!(lwe_vec.len(), chunks.len(), "LWE number blocks miss match");

    lwe_vec.iter_mut().zip(chunks.into_iter()).collect()
}
