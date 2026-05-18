//! Typed-state builder for [`PreKeyBundle`].
//!
//! `PrekeyBundleBuilder` provides compile-time enforcement of required
//! fields for pre-key bundle construction. Three phantom-typed states
//! track which required fields have been provided:
//!
//! - `identity_signing` (signing public key)
//! - `identity_kem` (KEM public key for DH2)
//! - `one_time_key` (KEM public key for DH1/DH3 and PQ encapsulation)
//!
//! Optional fields (`otk_key_id`, `timestamp`, `expiration`) are set via
//! plain setter methods on the in-progress builder.
//!
//! Calling `build()` is only available once all three required fields are
//! set; the type system rejects a `build()` call on a partial builder at
//! compile time, eliminating an entire class of misuse.
//!
//! The existing [`PreKeyBundle::new`] constructor stays available for
//! callers that prefer the direct API (operator decision Q5).

#[cfg(feature = "alloc")]
use core::marker::PhantomData;

#[cfg(feature = "alloc")]
use trelis_error::{CryptoError, Result};
#[cfg(feature = "alloc")]
use trelis_hybrid::{HybridKemPublicKey, HybridSigningPublicKey};

#[cfg(feature = "alloc")]
use crate::bundle::PreKeyBundle;

// ── Typed-state markers ────────────────────────────────────────────────

/// Marker: `identity_signing` has not been set.
#[cfg(feature = "alloc")]
#[derive(Clone, Copy, Debug)]
pub struct NoIdentitySigning;

/// Marker: `identity_signing` has been set.
#[cfg(feature = "alloc")]
#[derive(Clone, Copy, Debug)]
pub struct WithIdentitySigning;

/// Marker: `identity_kem` has not been set.
#[cfg(feature = "alloc")]
#[derive(Clone, Copy, Debug)]
pub struct NoIdentityKem;

/// Marker: `identity_kem` has been set.
#[cfg(feature = "alloc")]
#[derive(Clone, Copy, Debug)]
pub struct WithIdentityKem;

/// Marker: `one_time_key` has not been set.
#[cfg(feature = "alloc")]
#[derive(Clone, Copy, Debug)]
pub struct NoOneTimeKey;

/// Marker: `one_time_key` has been set.
#[cfg(feature = "alloc")]
#[derive(Clone, Copy, Debug)]
pub struct WithOneTimeKey;

// ── Builder ────────────────────────────────────────────────────────────

/// Builder for [`PreKeyBundle`] with compile-time enforcement of required
/// fields.
///
/// # Required Fields (compile-time-tracked)
///
/// - `identity_signing` — set via [`Self::with_identity_signing`]
/// - `identity_kem` — set via [`Self::with_identity_kem`]
/// - `one_time_key` — set via [`Self::with_one_time_key`]
///
/// # Optional Fields
///
/// - `otk_key_id` — defaults to `0` if not set
/// - `timestamp` — defaults to `0` (caller MUST set this for production use;
///   a freshly-built bundle with `timestamp = 0` will fail
///   `validate_timestamps` against any non-zero now)
/// - `expiration` — defaults to `u64::MAX` (never expires) if not set
///
/// # Example — Successful Build
///
/// ```no_run
/// use trelis_x3dh_pq::builder::PrekeyBundleBuilder;
/// use trelis_hybrid::{HybridKemKeypair, HybridSigningKeypair};
///
/// let signing = HybridSigningKeypair::generate().unwrap();
/// let kem = HybridKemKeypair::generate().unwrap();
/// let otk = HybridKemKeypair::generate().unwrap();
///
/// let bundle = PrekeyBundleBuilder::new()
///     .with_identity_signing(signing.public_key().clone())
///     .with_identity_kem(kem.public_key().clone())
///     .with_one_time_key(otk.public_key().clone())
///     .with_otk_key_id(0x1234_5678_9abc_def0)
///     .with_timestamp(1_700_000_000)
///     .with_expiration(1_700_000_000 + 7 * 24 * 3600)
///     .build()
///     .unwrap();
/// ```
///
/// # Compile-Time Misuse Rejection
///
/// Calling `build()` before all three required fields are set is rejected
/// at compile time. The following will NOT compile:
///
/// ```compile_fail
/// use trelis_x3dh_pq::builder::PrekeyBundleBuilder;
///
/// // Missing identity_signing, identity_kem, one_time_key — `build()` is
/// // only implemented on PrekeyBundleBuilder<WithIdentitySigning,
/// // WithIdentityKem, WithOneTimeKey>.
/// let _ = PrekeyBundleBuilder::new().build();
/// ```
#[cfg(feature = "alloc")]
pub struct PrekeyBundleBuilder<S = NoIdentitySigning, K = NoIdentityKem, O = NoOneTimeKey> {
    identity_signing: Option<HybridSigningPublicKey>,
    identity_kem: Option<HybridKemPublicKey>,
    one_time_key: Option<HybridKemPublicKey>,
    otk_key_id: u64,
    timestamp: u64,
    expiration: u64,
    _state: PhantomData<(S, K, O)>,
}

#[cfg(feature = "alloc")]
impl Default for PrekeyBundleBuilder<NoIdentitySigning, NoIdentityKem, NoOneTimeKey> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(feature = "alloc")]
impl PrekeyBundleBuilder<NoIdentitySigning, NoIdentityKem, NoOneTimeKey> {
    /// Creates a new empty builder.
    ///
    /// All required fields are unset; call `with_identity_signing`,
    /// `with_identity_kem`, and `with_one_time_key` (in any order) before
    /// `build()`.
    #[must_use]
    pub fn new() -> Self {
        Self {
            identity_signing: None,
            identity_kem: None,
            one_time_key: None,
            otk_key_id: 0,
            timestamp: 0,
            expiration: u64::MAX,
            _state: PhantomData,
        }
    }
}

#[cfg(feature = "alloc")]
impl<K, O> PrekeyBundleBuilder<NoIdentitySigning, K, O> {
    /// Sets the identity signing public key.
    ///
    /// Transitions the typed-state from `NoIdentitySigning` to
    /// `WithIdentitySigning`.
    #[must_use]
    pub fn with_identity_signing(
        self,
        identity_signing: HybridSigningPublicKey,
    ) -> PrekeyBundleBuilder<WithIdentitySigning, K, O> {
        PrekeyBundleBuilder {
            identity_signing: Some(identity_signing),
            identity_kem: self.identity_kem,
            one_time_key: self.one_time_key,
            otk_key_id: self.otk_key_id,
            timestamp: self.timestamp,
            expiration: self.expiration,
            _state: PhantomData,
        }
    }
}

#[cfg(feature = "alloc")]
impl<S, O> PrekeyBundleBuilder<S, NoIdentityKem, O> {
    /// Sets the identity KEM public key.
    ///
    /// Transitions the typed-state from `NoIdentityKem` to
    /// `WithIdentityKem`.
    #[must_use]
    pub fn with_identity_kem(
        self,
        identity_kem: HybridKemPublicKey,
    ) -> PrekeyBundleBuilder<S, WithIdentityKem, O> {
        PrekeyBundleBuilder {
            identity_signing: self.identity_signing,
            identity_kem: Some(identity_kem),
            one_time_key: self.one_time_key,
            otk_key_id: self.otk_key_id,
            timestamp: self.timestamp,
            expiration: self.expiration,
            _state: PhantomData,
        }
    }
}

#[cfg(feature = "alloc")]
impl<S, K> PrekeyBundleBuilder<S, K, NoOneTimeKey> {
    /// Sets the one-time KEM key.
    ///
    /// Transitions the typed-state from `NoOneTimeKey` to `WithOneTimeKey`.
    #[must_use]
    pub fn with_one_time_key(
        self,
        one_time_key: HybridKemPublicKey,
    ) -> PrekeyBundleBuilder<S, K, WithOneTimeKey> {
        PrekeyBundleBuilder {
            identity_signing: self.identity_signing,
            identity_kem: self.identity_kem,
            one_time_key: Some(one_time_key),
            otk_key_id: self.otk_key_id,
            timestamp: self.timestamp,
            expiration: self.expiration,
            _state: PhantomData,
        }
    }
}

#[cfg(feature = "alloc")]
impl<S, K, O> PrekeyBundleBuilder<S, K, O> {
    /// Sets the one-time key ID. Defaults to `0` if not called.
    #[must_use]
    pub fn with_otk_key_id(mut self, otk_key_id: u64) -> Self {
        self.otk_key_id = otk_key_id;
        self
    }

    /// Sets the creation timestamp (Unix seconds). Defaults to `0` if not
    /// called; a `0` timestamp on a production bundle will fail
    /// `validate_timestamps` for any non-zero `now`, so callers MUST set
    /// this in production code.
    #[must_use]
    pub fn with_timestamp(mut self, timestamp: u64) -> Self {
        self.timestamp = timestamp;
        self
    }

    /// Sets the expiration timestamp (Unix seconds). Defaults to
    /// `u64::MAX` (never expires) if not called.
    #[must_use]
    pub fn with_expiration(mut self, expiration: u64) -> Self {
        self.expiration = expiration;
        self
    }
}

#[cfg(feature = "alloc")]
impl PrekeyBundleBuilder<WithIdentitySigning, WithIdentityKem, WithOneTimeKey> {
    /// Builds the [`PreKeyBundle`].
    ///
    /// Only callable once all three required fields are set (enforced at
    /// compile time via the typed-state).
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::BundleTimestampInFuture`] if `expiration` is
    /// non-zero AND strictly less than `timestamp` (a runtime sanity
    /// check; the typed-state cannot catch this since both fields are
    /// `u64` with no ordering constraint at the type level).
    ///
    /// # Panics
    ///
    /// Does not panic in normal use — the typed-state guarantees that the
    /// three required field-`Option`s are populated. The `expect()` calls
    /// in the body are guarded by the `WithIdentitySigning`/
    /// `WithIdentityKem`/`WithOneTimeKey` typed-state markers, which can
    /// only be constructed by their respective `with_*` methods.
    pub fn build(self) -> Result<PreKeyBundle> {
        // Runtime sanity check on the optional ordering invariant.
        // `expiration == u64::MAX` (default) is treated as "no expiry" and
        // skips the check.
        if self.expiration != u64::MAX && self.expiration < self.timestamp {
            return Err(CryptoError::BundleTimestampInFuture);
        }

        // The typed-state guarantees these `expect`s are infallible — the
        // `WithIdentitySigning`/`WithIdentityKem`/`WithOneTimeKey` markers
        // are only constructed by their respective `with_*` methods which
        // populate the corresponding `Option`. The expect message is the
        // diagnostic that would surface if this invariant were ever
        // broken by a future refactor.
        #[allow(clippy::expect_used)]
        // AUDIT: typed-state guarantees these Option<T> values are Some(_)
        let bundle = PreKeyBundle {
            identity_signing: self
                .identity_signing
                .expect("typed-state guarantees identity_signing was set"),
            identity_kem: self
                .identity_kem
                .expect("typed-state guarantees identity_kem was set"),
            one_time_key: self
                .one_time_key
                .expect("typed-state guarantees one_time_key was set"),
            otk_key_id: self.otk_key_id,
            timestamp: self.timestamp,
            expiration: self.expiration,
        };
        Ok(bundle)
    }
}

#[cfg(all(test, feature = "alloc"))]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use trelis_hybrid::{HybridKemKeypair, HybridSigningKeypair};

    #[cfg_attr(miri, ignore)]
    #[test]
    fn builder_constructs_a_valid_bundle() {
        let signing = HybridSigningKeypair::generate().unwrap();
        let kem = HybridKemKeypair::generate().unwrap();
        let otk = HybridKemKeypair::generate().unwrap();

        let bundle = PrekeyBundleBuilder::new()
            .with_identity_signing(signing.public_key().clone())
            .with_identity_kem(kem.public_key().clone())
            .with_one_time_key(otk.public_key().clone())
            .with_otk_key_id(0x1234_5678_9abc_def0)
            .with_timestamp(1_700_000_000)
            .with_expiration(1_700_000_000 + 7 * 24 * 3600)
            .build()
            .expect("build should succeed with all required fields set");

        assert_eq!(bundle.otk_key_id, 0x1234_5678_9abc_def0);
        assert_eq!(bundle.timestamp, 1_700_000_000);
        assert_eq!(bundle.expiration, 1_700_000_000 + 7 * 24 * 3600);
    }

    #[cfg_attr(miri, ignore)]
    #[test]
    fn builder_with_fields_in_any_order() {
        // The typed-state markers are independent; order should not matter.
        let signing = HybridSigningKeypair::generate().unwrap();
        let kem = HybridKemKeypair::generate().unwrap();
        let otk = HybridKemKeypair::generate().unwrap();

        let bundle = PrekeyBundleBuilder::new()
            .with_one_time_key(otk.public_key().clone())
            .with_identity_kem(kem.public_key().clone())
            .with_identity_signing(signing.public_key().clone())
            .build();

        assert!(bundle.is_ok());
    }

    #[cfg_attr(miri, ignore)]
    #[test]
    fn builder_defaults_for_optional_fields() {
        let signing = HybridSigningKeypair::generate().unwrap();
        let kem = HybridKemKeypair::generate().unwrap();
        let otk = HybridKemKeypair::generate().unwrap();

        let bundle = PrekeyBundleBuilder::new()
            .with_identity_signing(signing.public_key().clone())
            .with_identity_kem(kem.public_key().clone())
            .with_one_time_key(otk.public_key().clone())
            .build()
            .unwrap();

        assert_eq!(bundle.otk_key_id, 0);
        assert_eq!(bundle.timestamp, 0);
        assert_eq!(bundle.expiration, u64::MAX);
    }

    #[cfg_attr(miri, ignore)]
    #[test]
    fn builder_rejects_expiration_before_timestamp() {
        let signing = HybridSigningKeypair::generate().unwrap();
        let kem = HybridKemKeypair::generate().unwrap();
        let otk = HybridKemKeypair::generate().unwrap();

        let res = PrekeyBundleBuilder::new()
            .with_identity_signing(signing.public_key().clone())
            .with_identity_kem(kem.public_key().clone())
            .with_one_time_key(otk.public_key().clone())
            .with_timestamp(2000)
            .with_expiration(1500)
            .build();

        assert!(matches!(res, Err(CryptoError::BundleTimestampInFuture)));
    }
}
