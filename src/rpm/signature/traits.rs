//! Trait abstractions of signing operations.

use crate::Timestamp;
use crate::errors::*;
use std::fmt::Debug;
use std::io;

use pgp::{
    crypto::hash::HashAlgorithm,
    packet::{SignatureConfig, SignatureType, Subpacket, SubpacketData},
    types::{KeyDetails, KeyVersion},
};

/// Signing trait to be implement for RPM signing.
pub trait Signing: Debug
where
    Self::Signature: AsRef<[u8]>,
{
    type Signature;
    fn sign(&self, data: impl io::Read, t: Timestamp) -> Result<Self::Signature, Error>;

    fn prepare_signature<T: KeyDetails>(
        signing_key: &T,
        t: Timestamp,
    ) -> Result<SignatureConfig, Error> {
        let t = pgp::types::Timestamp::from_secs(t.0);

        let hash_alg = HashAlgorithm::Sha256;
        let pub_alg = signing_key.algorithm();
        let mut sig_cfg = match signing_key.version() {
            KeyVersion::V6 => {
                let salt_len = hash_alg
                    .salt_len()
                    .expect("Sha256 always has a v6 salt length");
                let mut salt = vec![0u8; salt_len];
                getrandom::getrandom(&mut salt).expect("failed to generate random salt");
                SignatureConfig::v6_with_salt(SignatureType::Binary, pub_alg, hash_alg, salt)
            }
            _ => SignatureConfig::v4(SignatureType::Binary, pub_alg, hash_alg),
        };

        sig_cfg
            .hashed_subpackets
            .push(Subpacket::regular(SubpacketData::SignatureCreationTime(t))?);
        sig_cfg
            .hashed_subpackets
            .push(Subpacket::regular(SubpacketData::IssuerFingerprint(
                signing_key.fingerprint(),
            ))?);

        // v4 signatures include the legacy key ID; v6 signatures do not
        if signing_key.version() != KeyVersion::V6 {
            sig_cfg
                .hashed_subpackets
                .push(Subpacket::regular(SubpacketData::IssuerKeyId(
                    signing_key.legacy_key_id(),
                ))?);
        }

        Ok(sig_cfg)
    }
}

impl<T, S> Signing for &T
where
    T: Signing<Signature = S>,
    S: AsRef<[u8]>,
{
    type Signature = S;
    fn sign(&self, data: impl io::Read, t: Timestamp) -> Result<Self::Signature, Error> {
        T::sign(self, data, t)
    }
}

/// Verification trait to be implement for RPM signature verification.
pub trait Verifying: Debug
where
    Self::Signature: AsRef<[u8]>,
{
    type Signature;
    fn verify(&self, data: impl io::Read, signature: &[u8]) -> Result<(), Error>;
}

impl<T, S> Verifying for &T
where
    T: Verifying<Signature = S>,
    S: AsRef<[u8]>,
{
    type Signature = S;
    fn verify(&self, data: impl io::Read, signature: &[u8]) -> Result<(), Error> {
        T::verify(self, data, signature)
    }
}

pub mod key {

    /// Marker trait for key types.
    pub trait KeyType: super::Debug + Copy {}

    /// A secret key that should not be shared with any other party under any circumstance.
    #[derive(Debug, Clone, Copy)]
    pub struct Secret;

    /// A key publishable to the public.
    #[derive(Debug, Clone, Copy)]
    pub struct Public;

    impl KeyType for Secret {}
    impl KeyType for Public {}
}

/// Implement unreachable signer for empty tuple `()`
impl<T> Signing for std::marker::PhantomData<T> {
    type Signature = Vec<u8>;
    fn sign(&self, _data: impl io::Read, _t: Timestamp) -> Result<Self::Signature, Error> {
        unreachable!("you need to implement `sign` of the `Signing` trait")
    }
}

/// Implement unreachable verifier for the empty tuple`()`
impl<T> Verifying for std::marker::PhantomData<T> {
    type Signature = Vec<u8>;
    fn verify(&self, _data: impl io::Read, _x: &[u8]) -> Result<(), Error> {
        unreachable!("you need to implement `verify` of the `Verifying` trait")
    }
}
