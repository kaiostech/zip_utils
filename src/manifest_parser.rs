//! manifest.mf parser.
//! The format is:
//!
//! Manifest-Version: 1.0
//!
//! Name: index.html
//! Digest-Algorithms: MD5 SHA1 SHA256
//! MD5-Digest: iUWtv5hMIDJgcxuch3MVnQ==
//! SHA1-Digest: HyEG55l3oKhy/9n12J9pdXxJldo=
//! SHA256-Digest: MibzowBZALsAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
//!
//! ... other file entries

use std::io::{BufRead, BufReader, Read};

// We hardcode support for sha1 and sha256 only.
#[derive(Clone)]
pub struct ManifestEntry {
    pub name: String,
    pub sha1: Option<String>,
    pub sha256: Option<String>,
}

pub struct Manifest {
    pub version: String,
    pub entries: Vec<ManifestEntry>,
}

fn parse_new_line<B: BufRead>(reader: &mut B) -> Result<(String, String), ()> {
    let mut buf = String::new();

    let _ = reader.read_line(&mut buf).map_err(|_| ())?;
    let parts: Vec<&str> = buf.split(':').collect();
    if parts.len() != 2 {
        return Err(());
    }

    Ok((parts[0].trim().into(), parts[1].trim().into()))
}

pub fn read_manifest<R: Read>(input: R) -> Result<Manifest, ()> {
    let mut reader = BufReader::new(input);

    // Parse the header.
    let header = parse_new_line(&mut reader)?;
    if header.0 != "Manifest-Version" {
        return Err(());
    }
    let version = header.1;

    let mut buf = String::new();
    let empty = reader.read_line(&mut buf);
    if empty.is_err() {
        return Ok(Manifest {
            version,
            entries: vec![],
        });
    }

    let mut entries: Vec<ManifestEntry> = vec![];

    macro_rules! get_line {
        ($name:expr) => {
            match parse_new_line(&mut reader) {
                Err(()) => {
                    // println!("No new line 2 for {}", $name);
                    return Ok(Manifest { version, entries });
                }
                Ok(val) => {
                    if val.0 != $name {
                        return Ok(Manifest { version, entries });
                    }
                    val.1
                }
            }
        };
    }

    // Each iteration reads an entry. If we reach EOF, return with
    // what we currently have.
    loop {
        // Get the name.
        let name = get_line!("Name");

        let mut entry = ManifestEntry {
            name,
            sha1: None,
            sha256: None,
        };

        // Get the algorithms and hashed values.
        for algo in get_line!("Digest-Algorithms").split(' ') {
            let value = get_line!(format!("{}-Digest", algo));
            match algo {
                "SHA1" => entry.sha1 = Some(value),
                "SHA256" => entry.sha256 = Some(value),
                _ => {}
            }
        }
        // Make sure we have at least a digest to check.
        // If not we don't add the entry to the list of files, which will
        // make the overall check fail because of the missing entry.
        if entry.sha1.is_some() || entry.sha256.is_some() {
            entries.push(entry);
        }

        // Read the empty line, or EOF.
        let mut buf = String::new();
        let empty = reader.read_line(&mut buf);
        if empty.is_err() {
            return Ok(Manifest { version, entries });
        }
    }
}

// Reads the zigbert.sf and extract the SHA1-Digest-Manifest
pub fn read_signature_manifest<R: Read>(input: R) -> Result<String, ()> {
    let mut reader = BufReader::new(input);

    // Parse the header.
    let header = parse_new_line(&mut reader)?;
    if header.0 != "Signature-Version" {
        return Err(());
    }

    loop {
        let line = parse_new_line(&mut reader)?;
        if line.0 == "SHA1-Digest-Manifest" {
            return Ok(line.1);
        }
    }
}

#[test]
fn hash_manifest() {
    use std::fs::File;

    let file = File::open("test-fixtures/manifest.mf").unwrap();
    let manifest = read_manifest(file).unwrap();
    assert_eq!(manifest.version, "1.0");
    assert_eq!(manifest.entries.len(), 4);
    let entry = manifest.entries[2].clone();
    assert_eq!(entry.name, "style/icons/Default.png".to_string());
    assert_eq!(
        entry.sha1.unwrap(),
        "EEfSxfvlizAhlsfcnqZZwimA38A=".to_string()
    );
}

#[test]
fn signature_manifest() {
    use std::fs::File;

    let file = File::open("test-fixtures/zigbert.sf").unwrap();
    let hash = read_signature_manifest(file).unwrap();
    assert_eq!(hash, "pu2xSwnv0PYXFJk9yjAaGBBcQ4I=");
}
