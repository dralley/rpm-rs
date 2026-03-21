use clap::Parser;
use pgp::{
    adapter::RsaSigner,
    packet::PacketTrait,
    types::{KeyDetails, KeyVersion, Password, SigningKey, Timestamp},
};
use rpm::{
    Error, Package,
    signature::{Signing, pgp::Signer},
};
use rsa::{RsaPrivateKey, pkcs1v15};
use std::{fmt, io, path::PathBuf};

/// Sign an RPM with a random RPM key
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// RPM to sign
    #[arg(short, long)]
    input: PathBuf,

    /// RPM output after the signature
    #[arg(short, long)]
    output: PathBuf,
}

fn main() {
    let args = Args::parse();

    let mut rng = rand::thread_rng();
    let rsa_key = RsaPrivateKey::new(&mut rng, 2048).expect("failed to generate a key");
    let rsa_key = pkcs1v15::SigningKey::<sha2::Sha256>::new(rsa_key);

    // pgp::adapter::RsaSigner accept any key that implements [`signature::Keypair`] and
    // [`signature::PrehashSigner`].
    let rsa_signer =
        RsaSigner::new(rsa_key, KeyVersion::V4, Timestamp::now()).expect("create a PGP signer");

    let pgp_signer = HsmSigner {
        secret_key: rsa_signer,
    };

    let mut pkg = Package::open(args.input).expect("open source rpm");
    pkg.sign(pgp_signer)
        .expect("Sign the package with the private key");
    pkg.write_file(args.output).expect("write signed RPM");
}

pub struct HsmSigner<T> {
    secret_key: T,
}

impl<T> fmt::Debug for HsmSigner<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HsmSigner").finish_non_exhaustive()
    }
}

impl<T> Signing for HsmSigner<T>
where
    T: KeyDetails + SigningKey,
{
    type Signature = Vec<u8>;

    fn sign(&self, data: impl io::Read, t: rpm::Timestamp) -> Result<Self::Signature, Error> {
        let sig_cfg = Signer::prepare_signer_configuration(&self.secret_key, t)?;

        let signature_packet = sig_cfg
            .sign(&self.secret_key, &Password::empty(), data)
            .map_err(Error::SignError)?;

        let mut signature_bytes = Vec::with_capacity(1024);
        let mut cursor = io::Cursor::new(&mut signature_bytes);
        signature_packet
            .to_writer_with_header(&mut cursor)
            .map_err(Error::SignError)?;

        Ok(signature_bytes)
    }
}
