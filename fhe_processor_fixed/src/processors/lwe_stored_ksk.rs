use ::serde::{Deserialize, Serialize};
use tfhe::{
    boolean::prelude::{DecompositionBaseLog, DecompositionLevelCount, LweDimension},
    core_crypto::prelude::{
            encrypt_lwe_ciphertext_list, ByteRandomGenerator, CastFrom, CastInto,
            CiphertextModulus, Container, ContainerMut, ContiguousEntityContainer,
            ContiguousEntityContainerMut, CreateFrom, EncryptionRandomGenerator,
            LweCiphertextListCreationMetadata, LweCiphertextListMutView, LweCiphertextListView,
            LweSecretKey, LweSize, PlaintextListOwned, UnsignedInteger, UnsignedTorus,
        },
    shortint::{parameters::DispersionParameter, wopbs::PlaintextCount},
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LweStoredReusedKeyswitchKey<C: Container>
where
    C::Element: UnsignedInteger,
{
    data: C,
    decomp_base_log: DecompositionBaseLog,
    decomp_level_count: DecompositionLevelCount,
    input_lwe_size: LweSize,
    output_lwe_size: LweSize,
    lwe_size_diff: usize,
    ciphertext_modulus: CiphertextModulus<C::Element>,
}

impl<T: UnsignedInteger, C: Container<Element = T>> AsRef<[T]> for LweStoredReusedKeyswitchKey<C> {
    fn as_ref(&self) -> &[T] {
        self.data.as_ref()
    }
}

impl<T: UnsignedInteger, C: ContainerMut<Element = T>> AsMut<[T]>
    for LweStoredReusedKeyswitchKey<C>
{
    fn as_mut(&mut self) -> &mut [T] {
        self.data.as_mut()
    }
}

impl<Scalar: UnsignedInteger, C: Container<Element = Scalar>> LweStoredReusedKeyswitchKey<C> {
    pub fn from_container(
        container: C,
        decomp_base_log: DecompositionBaseLog,
        decomp_level_count: DecompositionLevelCount,
        input_lwe_size: LweSize,
        output_lwe_size: LweSize,
        lwe_size_diff: usize,
        ciphertext_modulus: CiphertextModulus<C::Element>,
    ) -> Self {
        assert!(
            container.container_len() > 0,
            "Got an empty container to create an LweStoredReusedKeyswitchKey"
        );
        assert!(
            container.container_len()
                % (decomp_level_count.0 * output_lwe_size.0 * 1 << decomp_base_log.0)
                == 0,
            "The provided container length is not valid. \
        It needs to be dividable by decomp_level_count * lwe_size_diff * 2^decomp_base_log: {}. \
        Got container length: {} and decomp_level_count: {decomp_level_count:?}, \
        output_lwe_size: {output_lwe_size:?}, decomp_base_log: {decomp_base_log:?}.",
            decomp_level_count.0 * output_lwe_size.0 * 1 << decomp_base_log.0,
            container.container_len()
        );

        Self {
            data: container,
            decomp_base_log,
            decomp_level_count,
            input_lwe_size,
            output_lwe_size,
            lwe_size_diff,
            ciphertext_modulus,
        }
    }

    /// Return the number of elements in an encryption of an input [`LweSecretKey`] element of the
    /// current [`LweStoredReusedKeyswitchKey`].
    pub fn input_key_element_encrypted_size(&self) -> usize {
        lwe_keyswitch_key_input_key_element_encrypted_size(
            self.decomp_level_count,
            self.decomp_base_log,
            self.output_lwe_size,
        )
    }

    /// Return the [`DecompositionBaseLog`] of the [`LweStoredReusedKeyswitchKey`].
    ///
    /// See [`LweStoredReusedKeyswitchKey::from_container`] for usage.
    pub fn decomposition_base_log(&self) -> DecompositionBaseLog {
        self.decomp_base_log
    }

    /// Return the [`DecompositionLevelCount`] of the [`LweStoredReusedKeyswitchKey`].
    ///
    /// See [`LweStoredReusedKeyswitchKey::from_container`] for usage.
    pub fn decomposition_level_count(&self) -> DecompositionLevelCount {
        self.decomp_level_count
    }

    /// Return the input [`LweDimension`] of the [`LweStoredReusedKeyswitchKey`].
    ///
    /// See [`LweStoredReusedKeyswitchKey::from_container`] for usage.
    pub fn input_key_lwe_dimension(&self) -> LweDimension {
        self.input_lwe_size.to_lwe_dimension()
    }

    /// Return the output [`LweDimension`] of the [`LweStoredReusedKeyswitchKey`].
    ///
    /// See [`LweStoredReusedKeyswitchKey::from_container`] for usage.
    pub fn output_key_lwe_dimension(&self) -> LweDimension {
        self.output_lwe_size.to_lwe_dimension()
    }

    /// Return the output [`LweSize`] of the [`LweStoredReusedKeyswitchKey`].
    ///
    /// See [`LweStoredReusedKeyswitchKey::from_container`] for usage.
    pub fn output_lwe_size(&self) -> LweSize {
        self.output_lwe_size
    }
    /// Return the input [`LweSize`] of the [`LweStoredReusedKeyswitchKey`].
    ///
    /// See [`LweStoredReusedKeyswitchKey::from_container`] for usage.
    pub fn input_lwe_size(&self) -> LweSize {
        self.input_lwe_size
    }

    /// Return the difference in [`LweSize`] between the input and output [`LweStoredReusedKeyswitchKey`].
    /// /// See [`LweStoredReusedKeyswitchKey::from_container`] for usage.
    pub fn lwe_size_diff(&self) -> usize {
        self.lwe_size_diff
    }

    /// Return a view of the [`LweStoredReusedKeyswitchKey`]. This is useful if an algorithm takes a view by
    /// value.
    pub fn as_view(&self) -> LweStoredReusedKeyswitchKeyView<'_, Scalar> {
        LweStoredReusedKeyswitchKey::from_container(
            self.as_ref(),
            self.decomp_base_log,
            self.decomp_level_count,
            self.input_lwe_size,
            self.output_lwe_size,
            self.lwe_size_diff,
            self.ciphertext_modulus,
        )
    }

    /// Consume the entity and return its underlying container.
    ///
    /// See [`LweStoredReusedKeyswitchKey::from_container`] for usage.
    pub fn into_container(self) -> C {
        self.data
    }

    pub fn as_lwe_ciphertext_list(&self) -> LweCiphertextListView<'_, Scalar> {
        LweCiphertextListView::from_container(
            self.as_ref(),
            self.output_lwe_size(),
            self.ciphertext_modulus(),
        )
    }

    pub fn ciphertext_modulus(&self) -> CiphertextModulus<C::Element> {
        self.ciphertext_modulus
    }
}

impl<Scalar: UnsignedInteger, C: ContainerMut<Element = Scalar>> LweStoredReusedKeyswitchKey<C> {
    /// Mutable variant of [`LweStoredReusedKeyswitchKey::as_view`].
    pub fn as_mut_view(&mut self) -> LweStoredReusedKeyswitchKeyMutView<'_, Scalar> {
        let decomp_base_log = self.decomp_base_log;
        let decomp_level_count = self.decomp_level_count;
        let output_lwe_size = self.output_lwe_size;
        let ciphertext_modulus = self.ciphertext_modulus;
        let input_lwe_size = self.input_lwe_size;
        let lwe_size_diff = self.lwe_size_diff;
        LweStoredReusedKeyswitchKey::from_container(
            self.as_mut(),
            decomp_base_log,
            decomp_level_count,
            input_lwe_size,
            output_lwe_size,
            lwe_size_diff,
            ciphertext_modulus,
        )
    }

    pub fn as_mut_lwe_ciphertext_list(&mut self) -> LweCiphertextListMutView<'_, Scalar> {
        let output_lwe_size = self.output_lwe_size();
        let ciphertext_modulus = self.ciphertext_modulus();
        LweCiphertextListMutView::from_container(self.as_mut(), output_lwe_size, ciphertext_modulus)
    }
}

/// An [`LweStoredReusedKeyswitchKey`] owning the memory for its own storage.
pub type LweStoredReusedKeyswitchKeyOwned<Scalar> = LweStoredReusedKeyswitchKey<Vec<Scalar>>;
/// An [`LweStoredReusedKeyswitchKey`] immutably borrowing memory for its own storage.
pub type LweStoredReusedKeyswitchKeyView<'data, Scalar> =
    LweStoredReusedKeyswitchKey<&'data [Scalar]>;
/// An [`LweStoredReusedKeyswitchKey`] mutably borrowing memory for its own storage.
pub type LweStoredReusedKeyswitchKeyMutView<'data, Scalar> =
    LweStoredReusedKeyswitchKey<&'data mut [Scalar]>;

impl<Scalar: UnsignedInteger> LweStoredReusedKeyswitchKeyOwned<Scalar> {
    /// Allocate memory and create a new owned [`LweStoredReusedKeyswitchKey`].
    ///
    /// # Note
    ///
    /// This function allocates a vector of the appropriate size and wraps it in the appropriate
    /// type. If you want to generate an [`LweStoredReusedKeyswitchKey`] you need to call
    /// [`crate::core_crypto::algorithms::generate_lwe_keyswitch_key`] using this key as output.
    ///
    /// See [`LweStoredReusedKeyswitchKey::from_container`] for usage.
    pub fn new(
        fill_with: Scalar,
        decomp_base_log: DecompositionBaseLog,
        decomp_level_count: DecompositionLevelCount,
        input_key_lwe_dimension: LweDimension,
        output_key_lwe_dimension: LweDimension,
        ciphertext_modulus: CiphertextModulus<Scalar>,
    ) -> Self {
        Self::from_container(
            vec![
                fill_with;
                (input_key_lwe_dimension.0 - output_key_lwe_dimension.0)
                    * lwe_keyswitch_key_input_key_element_encrypted_size(
                        decomp_level_count,
                        decomp_base_log,
                        output_key_lwe_dimension.to_lwe_size()
                    )
            ],
            decomp_base_log,
            decomp_level_count,
            input_key_lwe_dimension.to_lwe_size(),
            output_key_lwe_dimension.to_lwe_size(),
            input_key_lwe_dimension.0 - output_key_lwe_dimension.0,
            ciphertext_modulus,
        )
    }
}

#[derive(Clone, Copy)]
pub struct LweStoredReusedKeyswitchKeyCreationMetadata<Scalar: UnsignedInteger>(
    pub DecompositionBaseLog,
    pub DecompositionLevelCount,
    pub LweSize,
    pub LweSize,
    pub usize, // lwe_size_diff
    pub CiphertextModulus<Scalar>,
);

impl<Scalar: UnsignedInteger, C: Container<Element = Scalar>> CreateFrom<C>
    for LweStoredReusedKeyswitchKey<C>
{
    type Metadata = LweStoredReusedKeyswitchKeyCreationMetadata<Scalar>;

    #[inline]
    fn create_from(from: C, meta: Self::Metadata) -> Self {
        let LweStoredReusedKeyswitchKeyCreationMetadata(
            decomp_base_log,
            decomp_level_count,
            input_lwe_size,
            output_lwe_size,
            lwe_size_diff,
            ciphertext_modulus,
        ) = meta;
        Self::from_container(
            from,
            decomp_base_log,
            decomp_level_count,
            input_lwe_size,
            output_lwe_size,
            lwe_size_diff,
            ciphertext_modulus,
        )
    }
}
impl<Scalar: UnsignedInteger, C: Container<Element = Scalar>> ContiguousEntityContainer
    for LweStoredReusedKeyswitchKey<C>
{
    type Element = C::Element;

    type EntityViewMetadata = LweCiphertextListCreationMetadata<Self::Element>;

    type EntityView<'this> = LweCiphertextListView<'this, Self::Element>
    where
        Self: 'this;

    type SelfViewMetadata = LweStoredReusedKeyswitchKeyCreationMetadata<Self::Element>;

    type SelfView<'this> = LweStoredReusedKeyswitchKeyView<'this, Self::Element>
    where
        Self: 'this;

    fn get_entity_view_creation_metadata(&self) -> Self::EntityViewMetadata {
        LweCiphertextListCreationMetadata(self.output_lwe_size(), self.ciphertext_modulus())
    }

    fn get_entity_view_pod_size(&self) -> usize {
        self.input_key_element_encrypted_size()
    }

    fn get_self_view_creation_metadata(&self) -> Self::SelfViewMetadata {
        LweStoredReusedKeyswitchKeyCreationMetadata(
            self.decomposition_base_log(),
            self.decomposition_level_count(),
            self.input_lwe_size(),
            self.output_lwe_size(),
            self.input_lwe_size().0 - self.output_lwe_size().0,
            self.ciphertext_modulus(),
        )
    }
}

impl<Scalar: UnsignedInteger, C: ContainerMut<Element = Scalar>> ContiguousEntityContainerMut
    for LweStoredReusedKeyswitchKey<C>
{
    type EntityMutView<'this> = LweCiphertextListMutView<'this, Self::Element>
    where
        Self: 'this;

    type SelfMutView<'this> = LweStoredReusedKeyswitchKeyMutView<'this, Self::Element>
    where
        Self: 'this;
}

/// Return the number of elements in an encryption of an input [`LweSecretKey`] element for a
/// [`LweStoredReusedKeyswitchKey`] given a [`DecompositionLevelCount`] and output [`LweSize`].
pub fn lwe_keyswitch_key_input_key_element_encrypted_size(
    decomp_level_count: DecompositionLevelCount,
    decomp_base_log: DecompositionBaseLog,
    output_lwe_size: LweSize,
) -> usize {
    // One ciphertext per level encrypted under the output key
    output_lwe_size.0 * decomp_level_count.0 * (1 << decomp_base_log.0)
}
////////////////////////////////////////////////////////////////////////
/// key generation part
pub fn generate_lwe_stored_reused_keyswitch_key<
    Scalar,
    InputKeyCont,
    OutputKeyCont,
    KSKeyCont,
    Gen,
>(
    input_lwe_sk: &LweSecretKey<InputKeyCont>,
    output_lwe_sk: &LweSecretKey<OutputKeyCont>,
    lwe_keyswitch_key: &mut LweStoredReusedKeyswitchKey<KSKeyCont>,
    noise_parameters: impl DispersionParameter,
    generator: &mut EncryptionRandomGenerator<Gen>,
) where
    Scalar: UnsignedTorus + CastInto<usize> + CastFrom<usize>,
    InputKeyCont: Container<Element = Scalar>,
    OutputKeyCont: Container<Element = Scalar>,
    KSKeyCont: ContainerMut<Element = Scalar>,
    Gen: ByteRandomGenerator,
{
    assert!(
        lwe_keyswitch_key.input_key_lwe_dimension() == input_lwe_sk.lwe_dimension(),
        "The destination LweKeyswitchKey input LweDimension is not equal \
    to the input LweSecretKey LweDimension. Destination: {:?}, input: {:?}",
        lwe_keyswitch_key.input_key_lwe_dimension(),
        input_lwe_sk.lwe_dimension()
    );
    assert!(
        lwe_keyswitch_key.output_key_lwe_dimension() == output_lwe_sk.lwe_dimension(),
        "The destination LweKeyswitchKey output LweDimension is not equal \
    to the output LweSecretKey LweDimension. Destination: {:?}, output: {:?}",
        lwe_keyswitch_key.output_key_lwe_dimension(),
        output_lwe_sk.lwe_dimension()
    );
    let n = output_lwe_sk.lwe_dimension().0;
    for (input_key_element, output_key_element) in input_lwe_sk
        .as_ref()
        .iter()
        .zip(output_lwe_sk.as_ref().iter())
        .take(n)
    {
        assert!(
            input_key_element.eq(output_key_element),
            "The input key element is not compatible with the output key element, not a reused key. \
    Input: {:?}, output: {:?}",
            input_key_element,
            output_key_element
        );
    }

    let decomp_base_log = lwe_keyswitch_key.decomposition_base_log();
    let decomp_base = 1 << decomp_base_log.0;
    let decomp_level_count = lwe_keyswitch_key.decomposition_level_count();
    let ciphertext_modulus = lwe_keyswitch_key.ciphertext_modulus();
    assert!(ciphertext_modulus.is_compatible_with_native_modulus());

    // The plaintexts used to encrypt a key element will be stored in this buffer
    let mut decomposition_plaintexts_buffer = PlaintextListOwned::new(
        Scalar::ZERO,
        PlaintextCount(decomp_level_count.0 * 1 << decomp_base_log.0),
    );

    let base_half = (decomp_base as i64) / 2;
    let mut shift: usize ;

    for (input_key_element, mut keyswitch_key_block) in input_lwe_sk
        .as_ref()
        .iter()
        .skip(n)
        .zip(lwe_keyswitch_key.iter_mut())
    {
        // 填充 decomposition_plaintexts_buffer
        for level_idx in 0..decomp_level_count.0 {
            for t in -base_half..base_half {
                // t = {-B/2, ..., -1, 0, 1, ..., B/2 - 1}
                let buffer_idx = level_idx * decomp_base + (t + base_half) as usize;
                let mut tt: Scalar = int_to_scalar(t);

                tt *= *input_key_element;

                shift = Scalar::BITS - (decomp_base_log.0 * (level_idx+1));
                tt.shl_assign(shift);

                decomposition_plaintexts_buffer.as_mut()[buffer_idx] = tt;
            }
        }

        encrypt_lwe_ciphertext_list(
            output_lwe_sk,
            &mut keyswitch_key_block,
            &decomposition_plaintexts_buffer,
            noise_parameters,
            generator,
        );


    }

}

/// Allocate a new [`LWE stored reused version keyswitch key`](`LweStoredReusedKeyswitchKey`) and fill it with an actual keyswitching
/// key constructed from an input and an output key [`LWE secret key`](`LweSecretKey`).
///
/// See [`keyswitch_lwe_ciphertext`] for usage.
pub fn allocate_and_generate_new_stored_reused_lwe_keyswitch_key<
    Scalar,
    InputKeyCont,
    OutputKeyCont,
    Gen,
>(
    input_lwe_sk: &LweSecretKey<InputKeyCont>,
    output_lwe_sk: &LweSecretKey<OutputKeyCont>,
    decomp_base_log: DecompositionBaseLog,
    decomp_level_count: DecompositionLevelCount,
    noise_parameters: impl DispersionParameter,
    ciphertext_modulus: CiphertextModulus<Scalar>,
    generator: &mut EncryptionRandomGenerator<Gen>,
) -> LweStoredReusedKeyswitchKeyOwned<Scalar>
where
    Scalar: UnsignedTorus + CastFrom<usize> + CastInto<usize>,
    InputKeyCont: Container<Element = Scalar>,
    OutputKeyCont: Container<Element = Scalar>,
    Gen: ByteRandomGenerator,
{
    let mut new_lwe_keyswitch_key = LweStoredReusedKeyswitchKeyOwned::new(
        Scalar::ZERO,
        decomp_base_log,
        decomp_level_count,
        input_lwe_sk.lwe_dimension(),
        output_lwe_sk.lwe_dimension(),
        ciphertext_modulus,
    );

    generate_lwe_stored_reused_keyswitch_key(
        input_lwe_sk,
        output_lwe_sk,
        &mut new_lwe_keyswitch_key,
        noise_parameters,
        generator,
    );

    new_lwe_keyswitch_key
}

#[inline]
fn int_to_scalar<Scalar: UnsignedTorus + CastFrom<usize>>(t: i64) -> Scalar {
    if t >= 0 {
        Scalar::cast_from(t as usize)
    } else {
        Scalar::cast_from((-t) as usize).wrapping_neg()
    }
}
