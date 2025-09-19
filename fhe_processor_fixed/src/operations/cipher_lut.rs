use tfhe::core_crypto::{
    fft_impl::fft64::{
        c64,
        crypto::wop_pbs::{
            vertical_packing,
            vertical_packing_scratch,
        },
    },
};
use tfhe::{
    boolean::prelude::PolynomialSize,
    core_crypto::prelude::{
        ComputationBuffers, Fft, FourierGgswCiphertextList, LweCiphertext, PolynomialList,
    },
};
/// Pack multiple lookup tables into encrypted lookup tables 
/// (each lookup table is independently generated as a `PolynomialList`).
///
/// # Parameters
/// - `tables`: A collection of lookup tables, where each element is one table 
///   (e.g., different chunked sub-tables or different functional tables).
/// - `polynomial_size`: The polynomial degree (how many elements can fit 
///   in each GLWE polynomial).
/// - `delta`: Scaling factor (used in TFHE encoding).
///
/// # Returns
/// - `Vec<PolynomialList<Vec<u64>>>`: A vector of encrypted lookup tables, 
///   where each table corresponds to one `PolynomialList`.
///
/// # Example
/// ```ignore
/// let lut_lists = generate_lut_from_vecs(&split_tables, PolynomialSize(1024), 1 << 40);
/// // `lut_lists[i]` is the encrypted lookup table (PolynomialList) for the i-th table.
/// ```
pub fn generate_lut_from_vecs(
    tables: &[Vec<usize>],
    polynomial_size: PolynomialSize,
    delta: u64,
) -> Vec<PolynomialList<Vec<u64>>> {
    let mut result = Vec::with_capacity(tables.len());

    for (_, table) in tables.iter().enumerate() {
        let table_len = table.len();
        let num_poly = (table_len + polynomial_size.0 - 1) / polynomial_size.0;

        let mut flat: Vec<u64> = Vec::with_capacity(num_poly * polynomial_size.0);

        for poly_idx in 0..num_poly {
            for i in 0..polynomial_size.0 {
                let idx = poly_idx * polynomial_size.0 + i;
                let val = if idx < table_len {
                    (table[idx] as u64) * delta
                } else {
                    0
                };
                flat.push(val);
            }
        }

        let poly_list = PolynomialList::from_container(flat, polynomial_size);
        result.push(poly_list);
    }
    result
}

pub fn generate_lut_from_vecs_auto(
    tables: &[Vec<usize>],
    polynomial_size: PolynomialSize,
    delta: u64,
) -> (Vec<PolynomialList<Vec<u64>>>, usize) {
    assert!(!tables.is_empty(), "tables must not be empty");

    let table_len = tables[0].len();
    for t in tables.iter().skip(1) {
        assert!(
            t.len() == table_len,
            "all tables must have the same length: expected {}, got {}",
            table_len,
            t.len()
        );
    }

    let n = polynomial_size.0;
    let per_poly_capacity = n / table_len;

    // no packing
    if per_poly_capacity < 1 {
        let mut result = Vec::with_capacity(tables.len());

        for table in tables {
            let table_len = table.len();
            let num_poly = (table_len + n - 1) / n;

            let mut flat: Vec<u64> = Vec::with_capacity(num_poly * n);

            for poly_idx in 0..num_poly {
                for i in 0..n {
                    let idx = poly_idx * n + i;
                    let val = if idx < table_len {
                        (table[idx] as u64) * delta
                    } else {
                        0
                    };
                    flat.push(val);
                }
            }

            let poly_list = PolynomialList::from_container(flat, polynomial_size);
            result.push(poly_list);
        }

        return (result, 1);
    }

    // with packing
    let total_tables = tables.len();
    let num_groups = (total_tables + per_poly_capacity - 1) / per_poly_capacity;

    let mut result = Vec::with_capacity(num_groups);

    for g in 0..num_groups {
        let mut flat = vec![0u64; n];

        for s in 0..per_poly_capacity {
            let table_idx = g * per_poly_capacity + s;
            if table_idx >= total_tables {
                break;
            }

            // copy to [s*table_len .. s*table_len + table_len)
            let slot_base = s * table_len;
            let table = &tables[table_idx];

            for j in 0..table_len {
                flat[slot_base + j] = (table[j] as u64) * delta;
            }
        }

        let poly_list = PolynomialList::from_container(flat, polynomial_size);
        //now poly_list contain 1 poly only
        result.push(poly_list);
    }

    (result, per_poly_capacity)
}

/// TFHE vertical_packing lookup function for a single lookup table
///
/// # Parameters
/// - `lut`: The lookup table (`PolynomialList`)
/// - `lwe_out`: Output ciphertext (`LweCiphertext`, mutable)
/// - `ggsw_list`: GGSW key list
/// - `fft`: FFT context
/// - `buffer`: Temporary scratch buffer
/// - `lut_input_size`: Number of input bits (or total inputs) for the lookup table; 
///   must match the GLWE parameters
///
/// # Description
/// Performs a complete lookup using vertical_packing. 
/// The result is written into `lwe_out`.
pub fn tfhe_vertical_packing_lookup(
    lut: &PolynomialList<Vec<u64>>,
    lwe_out: &mut LweCiphertext<Vec<u64>>,
    ggsw_list: &FourierGgswCiphertextList<Vec<c64>>,
    fft: &Fft,
    buffer: &mut ComputationBuffers,
    lut_input_size: usize,
) {
    let _ = lut_input_size;
    // 确保buffer大小足够
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
    let stack = buffer.stack();

    vertical_packing(
        lut.as_view(),
        lwe_out.as_mut_view(),
        ggsw_list.as_view(),
        fft.as_view(),
        stack,
    );
}

/// Batch vertical_packing lookup for multiple lookup tables
///
/// # Parameters
/// - `luts`: Array of lookup tables (each a `PolynomialList`)
/// - `lwe_outs`: Array of output ciphertexts (each an `LweCiphertext`)
/// - Others: Same as above
pub fn tfhe_vertical_packing_multi_lookup(
    luts: &[PolynomialList<Vec<u64>>],
    lwe_outs: &mut [LweCiphertext<Vec<u64>>],
    ggsw_list: &FourierGgswCiphertextList<Vec<c64>>,
    fft: &Fft,
    buffer: &mut ComputationBuffers,
    lut_input_size: usize,
) {
    assert_eq!(luts.len(), lwe_outs.len());
    for (lut, lwe_out) in luts.iter().zip(lwe_outs.iter_mut()) {
        tfhe_vertical_packing_lookup(lut, lwe_out, ggsw_list, fft, buffer, lut_input_size);
    }
}
