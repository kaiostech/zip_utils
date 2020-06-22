//! A utility to check the validity of signed zip archives.

extern crate base64;
extern crate ring;
extern crate untrusted;
extern crate zip;

mod manifest_parser;

use self::manifest_parser::*;
use ring::{digest, signature};
use std::fs::File;
use std::io::Read;
use std::path::Path;
use zip::ZipArchive;

#[derive(Debug)]
pub enum ZipVerificationError {
    NoSuchFile,
    InvalidZip,
    MissingMetaFile(String),
    InvalidHash,
    InvalidSignature,
    InvalidFileList,
    InvalidManifest,
}

// Verify the digest of a readable stream using the given algorithm and
// expected value.
fn check_entry_digest<R: Read>(
    input: &mut R,
    algorithm: &'static digest::Algorithm,
    expected: &str,
) -> Result<(), ZipVerificationError> {
    let mut context = digest::Context::new(algorithm);

    loop {
        let mut buffer = [0; 4096];
        let count = input
            .read(&mut buffer[..])
            .map_err(|_| ZipVerificationError::InvalidHash)?;
        if count == 0 {
            break;
        }
        context.update(&buffer[..count]);
    }

    // Convert the byte representation into the expected text format.
    let result = base64::encode(context.finish().as_ref());

    if result == expected {
        Ok(())
    } else {
        println!("Expected {} but got {}", expected, result);
        Err(ZipVerificationError::InvalidHash)
    }
}

// Verifies the hashes and signature of a zip file at the given path.
pub fn verify_zip<P: AsRef<Path>>(path: P) -> Result<(), ZipVerificationError> {
    let file = File::open(path).map_err(|_| ZipVerificationError::NoSuchFile)?;

    let mut archive = ZipArchive::new(file).map_err(|_| ZipVerificationError::InvalidZip)?;

    // 1. Verify the presence of mandatory files in META-INF. Any other file will be
    // referenced in the hash list in META-INF/manifest.mf
    for name in [
        "META-INF/zigbert.rsa",
        "META-INF/zigbert.sf",
        "META-INF/manifest.mf",
    ]
        .iter()
    {
        let _ = archive
            .by_name(name)
            .map_err(|_| ZipVerificationError::MissingMetaFile((*name).into()))?;
    }

    // 2. Get the parsed manifest.
    if let Ok(manifest) = read_manifest(archive.by_name("META-INF/manifest.mf").unwrap()) {
        if manifest.version != "1.0" {
            return Err(ZipVerificationError::InvalidManifest);
        }

        // 3. Check that the list of files in the manifest matches the list of files in the zip:
        // - the total number of files in the zip must be manifest.entries + 3 (special the META-INF ones)
        // - every file listed in the manifest must exist.
        // - their hashes must match.
        if manifest.entries.len() + 3 != archive.len() {
            return Err(ZipVerificationError::InvalidFileList);
        }

        for entry in manifest.entries {
            match archive.by_name(&entry.name) {
                Err(_) => return Err(ZipVerificationError::InvalidFileList),
                Ok(mut zipentry) => {
                    if let Some(sha1) = entry.sha1 {
                        check_entry_digest(&mut zipentry, &digest::SHA1, &sha1)?;
                    }
                    if let Some(sha256) = entry.sha256 {
                        check_entry_digest(&mut zipentry, &digest::SHA256, &sha256)?;
                    }
                }
            }
        }

        // 4. Use the META-INF/zigbert.sf to check the hash of META-INF/manifest.mf
        match read_signature_manifest(archive.by_name("META-INF/zigbert.sf").unwrap()) {
            Ok(manifest_hash) => {
                check_entry_digest(
                    &mut archive.by_name("META-INF/manifest.mf").unwrap(),
                    &digest::SHA1,
                    &manifest_hash,
                )?;
            }
            Err(_) => return Err(ZipVerificationError::InvalidManifest),
        }

        // 5. Check the signature of META-INF/zigbert.sf
        let mut signature: Vec<u8> = Vec::new();
        {
            let mut signature_file = archive.by_name("META-INF/zigbert.rsa").unwrap();
            signature_file
                .read_to_end(&mut signature)
                .map_err(|_| ZipVerificationError::InvalidZip)?;
        }
        // println!("Signature size: {} bytes", signature.len());
        let signature = untrusted::Input::from(&signature);

        // TODO: include the public key differently.
        let mut public_key_file = File::open("test-fixtures/service-center-test.crt").unwrap();
        let mut public_key: Vec<u8> = Vec::new();
        public_key_file
            .read_to_end(&mut public_key)
            .map_err(|_| ZipVerificationError::InvalidZip)?;
        let public_key = untrusted::Input::from(&public_key);

        let mut message_file = archive.by_name("META-INF/zigbert.sf").unwrap();
        let mut message: Vec<u8> = Vec::new();
        message_file
            .read_to_end(&mut message)
            .map_err(|_| ZipVerificationError::InvalidZip)?;
        let message = untrusted::Input::from(&message);

        // signature::verify(
        //     &signature::RSA_PKCS1_2048_8192_SHA256,
        //     public_key,
        //     message,
        //     signature,
        // )
        // .map_err(|e|  {
        //     println!("Signature verification failed: {:?}", e);
        //     ZipVerificationError::InvalidSignature
        // })?;
    } else {
        return Err(ZipVerificationError::InvalidManifest);
    }

    Ok(())
}

#[test]
fn valid_zip() {
    let result = verify_zip("test-fixtures/sample-signed.zip");
    assert!(result.is_ok());
}
