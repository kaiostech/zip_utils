use chrono::NaiveDateTime;
use openssl::asn1::Asn1Time;
use openssl::x509;
use simple_asn1::*;

use crate::ZipVerificationError;
use ring::digest;

#[derive(Debug)]
pub struct RsaInfo {
    pub certs_rsa: Vec<Vec<u8>>,
    pub sf_dig: Vec<u8>,
    pub sf_alg: &'static digest::Algorithm,
}

// Given the time as string format to determine the validity
fn check_expiry(start: &str, end: &str) -> Result<(), ZipVerificationError> {
    if start.len() < 4 || end.len() < 4 {
        return Err(ZipVerificationError::CertificateExpired);
    }

    // Jul  1 17:17:40 2020 GMT
    // Jan 14 07:51:52 2017 GMT
    let now_time = Asn1Time::days_from_now(0).unwrap();
    let now = now_time.as_ref();
    let now = format!("{}", now);

    let start_dt = NaiveDateTime::parse_from_str(&start[..start.len() - 4], "%b%d%H:%M:%S%Y")
        .map_err(|_| ZipVerificationError::CertificateExpired)?;
    let end_dt = NaiveDateTime::parse_from_str(&end[..end.len() - 4], "%b%d%H:%M:%S%Y")
        .map_err(|_| ZipVerificationError::CertificateExpired)?;
    let now_dt = NaiveDateTime::parse_from_str(&now[..now.len() - 4], "%b%d%H:%M:%S%Y")
        .map_err(|_| ZipVerificationError::CertificateExpired)?;

    if start_dt.timestamp() > now_dt.timestamp() || end_dt.timestamp() < now_dt.timestamp() {
        return Err(ZipVerificationError::CertificateExpired);
    }

    Ok(())
}

fn verify_cert_sig(
    certs_raw: &[Vec<u8>],
    root_cert_raw: &[u8],
) -> Result<(), ZipVerificationError> {
    let mut success = false;
    for cert_raw in certs_raw {
        let cert = x509::X509::from_der(&cert_raw)?;
        let cert_root = openssl::x509::X509::from_der(&root_cert_raw)?;

        let root_start = cert_root.not_before();
        let root_end = cert_root.not_after();
        let start = format!("{}", root_start);
        let end = format!("{}", root_end);
        let _ = check_expiry(&start, &end)?;

        let root_pub_key = cert_root.public_key()?;
        success = cert.verify(&root_pub_key)?;

        if success {
            break;
        }
    }

    if !success {
        return Err(ZipVerificationError::InvalidSignature);
    }

    Ok(())
}

fn parse_rsa(rsa_raw: &[u8]) -> Result<RsaInfo, ZipVerificationError> {
    let mut rsa_info = RsaInfo {
        certs_rsa: vec![],
        sf_dig: vec![],
        sf_alg: &digest::SHA1_FOR_LEGACY_USE_ONLY,
    };

    let vec_asn1_block = simple_asn1::from_der(&rsa_raw)?;

    // Sequence -> ObjectIdentifier
    let obj1 = match vec_asn1_block[0] {
        ASN1Block::Sequence(_, ref item) => item,
        _ => return Err(ZipVerificationError::DerefASN1Error),
    };

    // Sequence -> ContextSpecific
    let obj2 = match obj1[1] {
        ASN1Block::Explicit(_, _, _, ref item) => item,
        _ => return Err(ZipVerificationError::DerefASN1Error),
    };

    // Sequence -> ContextSpecific -> Sequence []
    let obj1_2_1 = match **obj2 {
        ASN1Block::Sequence(_, ref item) => item,
        _ => return Err(ZipVerificationError::DerefASN1Error),
    };

    rsa_info.certs_rsa = parse_cert(&obj1_2_1)?;

    // Sequence -> ContextSpecific -> Sequence -> Set -> Sequence
    let empty_v = vec![];
    let vec1_2_1_4_0 = match obj1_2_1[4] {
        ASN1Block::Set(_, ref item) => {
            match item[0] {
                ASN1Block::Sequence(_, ref seq) => seq,
                _ => &empty_v,
            }
        }
        _ => &empty_v,
    };

    // Sequence -> ContextSpecific -> Sequence -> Set -> Sequence
    // For Digest algorithm
    let null_oid = simple_asn1::oid!(0);
    let oid_alg = match vec1_2_1_4_0[2] {
        ASN1Block::Sequence(_, ref seq_items) => {
            match seq_items[0] {
                ASN1Block::ObjectIdentifier(_, ref id) => id,
                _ => &null_oid,
            }
        }
        _ => &null_oid,
    };

    let mut sf_alg = &digest::SHA1_FOR_LEGACY_USE_ONLY;
    if oid_alg == simple_asn1::oid!(2, 16, 840, 1, 101, 3, 4, 2, 1) {
        sf_alg = &digest::SHA256;
    } else if oid_alg == simple_asn1::oid!(2, 16, 840, 1, 101, 3, 4, 2, 2) {
        sf_alg = &digest::SHA384;
    } else if oid_alg == simple_asn1::oid!(2, 16, 840, 1, 101, 3, 4, 2, 3) {
        sf_alg = &digest::SHA512;
    }
    rsa_info.sf_alg = &sf_alg;

    // Sequence -> ContextSpecific -> Sequence -> Set -> Sequence -> ContextSpecific(Unknown)
    let null_vec = [].to_vec();
    let vec1_2_1_4_0_3 = match vec1_2_1_4_0[3] {
        ASN1Block::Unknown(_, _, _, _, ref raw) => raw,
        _ => &null_vec,
    };

    // This is unknow format, need this trick(from_der) to parse underlying format:
    // Array of 3 Sequnces
    let vec_msg_dig = simple_asn1::from_der(&vec1_2_1_4_0_3)?;

    // For sf messageDigest
    let empty_v0 = [0].to_vec();
    let sf_dig = match vec_msg_dig[2] {
        ASN1Block::Sequence(_, ref seq_items) => {
            let null_oid = simple_asn1::oid!(0);
            let oid = match seq_items[0] {
                ASN1Block::ObjectIdentifier(_, ref id) => id,
                _ => &null_oid,
            };

            // OBJECTIDENTIFIER 1.2.840.113549.1.9.4 (messageDigest)
            let id_msg_dig = simple_asn1::oid!(1, 2, 840, 113549, 1, 9, 4);
            if oid == id_msg_dig {
                match seq_items[1] {
                    ASN1Block::Set(_, ref set_itmes) => {
                        if !set_itmes.is_empty() {
                            match set_itmes[0] {
                                ASN1Block::OctetString(_, ref msg) => msg,
                                _ => &empty_v0,
                            }
                        } else {
                            &empty_v0
                        }
                    }
                    _ => &empty_v0,
                }
            } else {
                &empty_v0
            }
        }
        _ => &empty_v0,
    };

    if sf_dig == &empty_v0 {
        return Err(ZipVerificationError::DerefASN1Error);
    }
    rsa_info.sf_dig = sf_dig.to_vec();

    Ok(rsa_info)
}

fn parse_cert(blocks: &[ASN1Block]) -> Result<Vec<Vec<u8>>, ZipVerificationError> {
    // Sequence -> ContextSpecific -> Sequence -> ContextSpecific
    if blocks.len() < 4 {
        return Err(ZipVerificationError::DerefASN1Error);
    }

    let mut certs_vec = vec![];
    match blocks[3] {
        ASN1Block::Explicit(_, _, _, ref item) => {
            let item_unbox = *item.clone();
            let cert = simple_asn1::to_der(&item_unbox)?;
            certs_vec.push(cert);
        }
        ASN1Block::Unknown(_, _, _, _, ref raw) => {
            let seqs = simple_asn1::from_der(&raw)?;
            for cert in seqs {
                let cert_raw = simple_asn1::to_der(&cert)?;
                certs_vec.push(cert_raw);
            }
        }
        _ => return Err(ZipVerificationError::DerefASN1Error),
    };

    if certs_vec.is_empty() {
        return Err(ZipVerificationError::DerefASN1Error);
    }

    Ok(certs_vec)
}

// compare computed signature and the parsed signature from .rsa
fn verify_sf_sig(
    sf_dig: Vec<u8>,
    sf_alg: &'static digest::Algorithm,
    sf_raw: Vec<u8>,
) -> Result<(), ZipVerificationError> {
    let mut context = digest::Context::new(&sf_alg);
    context.update(&sf_raw);
    let sf_dig_calc = context.finish();

    if sf_dig != sf_dig_calc.as_ref() {
        return Err(ZipVerificationError::InvalidSignature);
    }

    Ok(())
}

pub fn verify(
    rsa_raw: &[u8],
    sf_raw: &[u8],
    root_cert_raw: &[u8],
) -> Result<(), ZipVerificationError> {
    let rsa_info = parse_rsa(rsa_raw)?;
    let _ = verify_cert_sig(&rsa_info.certs_rsa, root_cert_raw)?;
    let _ = verify_sf_sig(rsa_info.sf_dig, &rsa_info.sf_alg, sf_raw.to_vec())?;

    Ok(())
}

#[test]
fn test_parse_rsa() {
    use std::fs::File;
    use std::io::Read;

    // sha1 test key signed
    let mut rsa_file = File::open("test-fixtures/zigbert.rsa").unwrap();
    let mut rsa_raw: Vec<u8> = Vec::new();
    rsa_file.read_to_end(&mut rsa_raw).unwrap();
    let expected_cert = vec![
        48, 130, 3, 157, 48, 130, 2, 133, 160, 3, 2, 1, 2, 2, 4, 1, 0, 0, 0, 48, 13, 6, 9, 42, 134,
        72, 134, 247, 13, 1, 1, 11, 5, 0, 48, 113, 49, 22, 48, 20, 6, 3, 85, 4, 3, 12, 13, 75, 97,
        105, 79, 83, 32, 84, 101, 115, 116, 32, 67, 65, 49, 27, 48, 25, 6, 3, 85, 4, 11, 12, 18,
        75, 97, 105, 79, 83, 32, 84, 101, 115, 116, 32, 83, 105, 103, 110, 105, 110, 103, 49, 19,
        48, 17, 6, 3, 85, 4, 10, 12, 10, 75, 97, 105, 79, 83, 32, 84, 101, 115, 116, 49, 11, 48, 9,
        6, 3, 85, 4, 7, 12, 2, 68, 69, 49, 11, 48, 9, 6, 3, 85, 4, 8, 12, 2, 68, 69, 49, 11, 48, 9,
        6, 3, 85, 4, 6, 19, 2, 85, 83, 48, 30, 23, 13, 49, 55, 48, 49, 49, 52, 48, 55, 53, 49, 53,
        54, 90, 23, 13, 50, 55, 48, 49, 49, 50, 48, 55, 53, 49, 53, 54, 90, 48, 118, 49, 27, 48,
        25, 6, 3, 85, 4, 3, 12, 18, 75, 97, 105, 79, 83, 32, 84, 101, 115, 116, 32, 83, 105, 103,
        110, 105, 110, 103, 49, 27, 48, 25, 6, 3, 85, 4, 11, 12, 18, 75, 97, 105, 79, 83, 32, 84,
        101, 115, 116, 32, 83, 105, 103, 110, 105, 110, 103, 49, 19, 48, 17, 6, 3, 85, 4, 10, 12,
        10, 75, 97, 105, 79, 83, 32, 84, 101, 115, 116, 49, 11, 48, 9, 6, 3, 85, 4, 7, 12, 2, 68,
        69, 49, 11, 48, 9, 6, 3, 85, 4, 8, 12, 2, 68, 69, 49, 11, 48, 9, 6, 3, 85, 4, 6, 19, 2, 85,
        83, 48, 130, 1, 34, 48, 13, 6, 9, 42, 134, 72, 134, 247, 13, 1, 1, 1, 5, 0, 3, 130, 1, 15,
        0, 48, 130, 1, 10, 2, 130, 1, 1, 0, 198, 253, 105, 226, 224, 163, 49, 71, 6, 122, 215, 16,
        81, 26, 51, 70, 0, 133, 120, 197, 85, 234, 68, 72, 218, 73, 9, 100, 121, 46, 160, 199, 158,
        110, 22, 88, 236, 159, 179, 135, 152, 3, 226, 193, 140, 90, 241, 26, 167, 196, 207, 85, 58,
        40, 9, 74, 93, 216, 206, 158, 12, 239, 119, 112, 231, 19, 64, 168, 133, 41, 34, 67, 56,
        122, 104, 5, 96, 199, 54, 40, 130, 169, 191, 249, 53, 176, 151, 71, 109, 3, 93, 69, 85, 81,
        57, 117, 118, 120, 94, 93, 243, 128, 20, 36, 125, 53, 173, 180, 83, 115, 107, 132, 226, 61,
        248, 161, 21, 8, 170, 43, 12, 26, 209, 208, 108, 80, 148, 110, 167, 93, 1, 148, 242, 153,
        201, 196, 159, 149, 97, 105, 187, 33, 130, 224, 149, 156, 255, 5, 133, 180, 144, 105, 51,
        92, 180, 134, 9, 41, 134, 233, 193, 239, 20, 113, 123, 66, 223, 109, 184, 31, 32, 168, 14,
        54, 77, 219, 41, 195, 71, 137, 117, 163, 78, 220, 63, 245, 117, 44, 163, 125, 156, 60, 157,
        122, 221, 75, 251, 99, 156, 6, 27, 126, 201, 234, 167, 208, 73, 235, 225, 126, 207, 1, 178,
        182, 106, 53, 219, 30, 45, 240, 109, 241, 133, 22, 162, 55, 3, 218, 78, 51, 112, 142, 201,
        9, 38, 227, 116, 136, 83, 230, 55, 156, 129, 12, 127, 41, 108, 9, 115, 124, 49, 20, 66,
        240, 242, 245, 2, 3, 1, 0, 1, 163, 56, 48, 54, 48, 12, 6, 3, 85, 29, 19, 1, 1, 255, 4, 2,
        48, 0, 48, 14, 6, 3, 85, 29, 15, 1, 1, 255, 4, 4, 3, 2, 7, 128, 48, 22, 6, 3, 85, 29, 37,
        1, 1, 255, 4, 12, 48, 10, 6, 8, 43, 6, 1, 5, 5, 7, 3, 3, 48, 13, 6, 9, 42, 134, 72, 134,
        247, 13, 1, 1, 11, 5, 0, 3, 130, 1, 1, 0, 125, 62, 26, 178, 35, 135, 48, 77, 172, 107, 160,
        134, 33, 206, 52, 206, 184, 181, 127, 132, 140, 222, 20, 53, 62, 250, 21, 92, 131, 189,
        240, 31, 80, 184, 88, 255, 144, 59, 97, 95, 241, 98, 130, 198, 196, 199, 61, 202, 69, 248,
        180, 151, 97, 229, 45, 253, 6, 80, 227, 108, 27, 176, 101, 154, 152, 221, 135, 40, 24, 92,
        63, 251, 39, 250, 221, 5, 244, 182, 239, 94, 96, 30, 188, 188, 222, 203, 170, 208, 142, 92,
        158, 88, 237, 200, 25, 142, 212, 13, 220, 220, 207, 82, 84, 139, 138, 205, 100, 236, 113,
        33, 189, 183, 53, 235, 127, 243, 69, 212, 39, 184, 68, 101, 187, 76, 250, 79, 195, 18, 46,
        164, 165, 16, 134, 18, 81, 214, 125, 18, 69, 121, 102, 208, 28, 154, 115, 15, 153, 72, 9,
        5, 157, 213, 17, 20, 28, 159, 86, 22, 89, 69, 13, 250, 150, 164, 70, 222, 66, 250, 228,
        134, 210, 20, 162, 76, 49, 166, 206, 153, 254, 176, 63, 35, 229, 139, 84, 121, 132, 202,
        155, 129, 38, 131, 43, 35, 83, 26, 45, 241, 21, 135, 42, 154, 136, 57, 149, 157, 65, 80,
        170, 126, 8, 106, 29, 242, 79, 188, 30, 11, 138, 131, 57, 89, 156, 43, 107, 147, 227, 173,
        218, 194, 120, 60, 48, 133, 223, 251, 37, 146, 210, 124, 165, 201, 212, 5, 246, 159, 41,
        81, 202, 188, 146, 81, 105, 220, 83, 53,
    ];
    let expected_dig = vec![
        129, 200, 224, 115, 210, 213, 48, 215, 120, 126, 128, 121, 0, 135, 139, 126, 16, 245, 49,
        249,
    ];
    let rsa_info = parse_rsa(&rsa_raw).unwrap();
    assert_eq!(rsa_info.certs_rsa.len(), 1);
    assert_eq!(rsa_info.certs_rsa[0], expected_cert);
    assert_eq!(rsa_info.sf_dig, expected_dig);
    assert_eq!(rsa_info.sf_alg, &digest::SHA1_FOR_LEGACY_USE_ONLY);

    // sha256 test key signed
    let mut rsa_file = File::open("test-fixtures/sha256.rsa").unwrap();
    let mut rsa_raw: Vec<u8> = Vec::new();
    rsa_file.read_to_end(&mut rsa_raw).unwrap();
    let rsa_info = parse_rsa(&rsa_raw).unwrap();
    assert_eq!(rsa_info.certs_rsa.is_empty(), false);
    assert_eq!(rsa_info.sf_dig.is_empty(), false);
    assert_eq!(rsa_info.sf_alg, &digest::SHA256);
}

#[test]
fn test_rsa_with_more_certs() {
    use std::fs::File;
    use std::io::Read;

    let mut rsa_file = File::open("test-fixtures/2certs.rsa").unwrap();
    let mut rsa_raw: Vec<u8> = Vec::new();
    rsa_file.read_to_end(&mut rsa_raw).unwrap();
    let cert0 = vec![
        48, 130, 5, 87, 48, 130, 3, 63, 160, 3, 2, 1, 2, 2, 2, 16, 6, 48, 13, 6, 9, 42, 134, 72,
        134, 247, 13, 1, 1, 11, 5, 0, 48, 116, 49, 11, 48, 9, 6, 3, 85, 4, 6, 19, 2, 85, 83, 49,
        11, 48, 9, 6, 3, 85, 4, 8, 12, 2, 68, 69, 49, 20, 48, 18, 6, 3, 85, 4, 10, 12, 11, 75, 97,
        105, 79, 83, 32, 83, 116, 97, 103, 101, 49, 36, 48, 34, 6, 3, 85, 4, 11, 12, 27, 75, 97,
        105, 79, 83, 32, 83, 116, 97, 103, 101, 32, 83, 105, 103, 110, 105, 110, 103, 32, 83, 101,
        114, 118, 105, 99, 101, 49, 28, 48, 26, 6, 3, 85, 4, 3, 12, 19, 75, 97, 105, 79, 83, 32,
        83, 116, 97, 103, 101, 32, 82, 111, 111, 116, 32, 67, 65, 48, 30, 23, 13, 50, 48, 48, 51,
        50, 51, 48, 51, 52, 52, 53, 49, 90, 23, 13, 50, 49, 48, 52, 48, 50, 48, 51, 52, 52, 53, 49,
        90, 48, 129, 156, 49, 11, 48, 9, 6, 3, 85, 4, 6, 19, 2, 85, 83, 49, 11, 48, 9, 6, 3, 85, 4,
        8, 12, 2, 68, 69, 49, 14, 48, 12, 6, 3, 85, 4, 7, 12, 5, 68, 111, 118, 101, 114, 49, 32,
        48, 30, 6, 3, 85, 4, 10, 12, 23, 75, 97, 105, 79, 83, 32, 84, 101, 99, 104, 110, 111, 108,
        111, 103, 105, 101, 115, 32, 73, 110, 99, 46, 49, 35, 48, 33, 6, 3, 85, 4, 11, 12, 26, 75,
        97, 105, 79, 83, 32, 80, 108, 117, 115, 32, 83, 105, 103, 110, 105, 110, 103, 32, 83, 101,
        114, 118, 105, 99, 101, 49, 41, 48, 39, 6, 3, 85, 4, 3, 12, 32, 75, 97, 105, 79, 83, 32,
        80, 108, 117, 115, 32, 83, 116, 97, 103, 101, 32, 83, 105, 103, 110, 105, 110, 103, 32, 83,
        101, 114, 118, 105, 99, 101, 48, 130, 1, 34, 48, 13, 6, 9, 42, 134, 72, 134, 247, 13, 1, 1,
        1, 5, 0, 3, 130, 1, 15, 0, 48, 130, 1, 10, 2, 130, 1, 1, 0, 203, 116, 5, 134, 49, 240, 102,
        42, 46, 243, 65, 176, 85, 98, 148, 217, 106, 74, 27, 164, 168, 188, 48, 88, 62, 124, 239,
        227, 222, 175, 28, 88, 234, 170, 68, 225, 98, 146, 251, 127, 162, 242, 146, 3, 163, 74,
        246, 172, 216, 112, 12, 142, 48, 167, 237, 206, 154, 184, 87, 251, 90, 159, 13, 163, 163,
        71, 186, 150, 15, 84, 60, 170, 248, 16, 54, 75, 84, 142, 162, 91, 195, 169, 135, 85, 177,
        4, 44, 228, 206, 243, 5, 38, 191, 153, 150, 137, 81, 12, 87, 7, 234, 34, 94, 60, 63, 46,
        208, 195, 99, 9, 99, 59, 91, 230, 192, 113, 165, 133, 12, 16, 136, 183, 161, 87, 128, 122,
        252, 91, 238, 87, 168, 212, 138, 60, 223, 113, 61, 29, 161, 162, 222, 13, 227, 171, 121,
        220, 13, 181, 203, 253, 159, 147, 97, 45, 129, 185, 202, 190, 1, 126, 36, 109, 151, 221,
        142, 62, 59, 203, 65, 44, 202, 182, 69, 171, 177, 244, 204, 209, 203, 163, 17, 153, 172,
        172, 128, 75, 13, 227, 57, 200, 170, 247, 166, 235, 32, 139, 136, 68, 16, 222, 216, 78,
        138, 122, 100, 77, 163, 86, 2, 192, 149, 64, 208, 170, 129, 181, 63, 45, 219, 13, 31, 15,
        170, 220, 251, 0, 54, 16, 52, 87, 83, 165, 18, 106, 6, 88, 176, 186, 90, 186, 168, 250,
        214, 129, 198, 162, 223, 179, 209, 192, 48, 32, 156, 115, 88, 75, 2, 3, 1, 0, 1, 163, 129,
        201, 48, 129, 198, 48, 12, 6, 3, 85, 29, 19, 1, 1, 255, 4, 2, 48, 0, 48, 17, 6, 9, 96, 134,
        72, 1, 134, 248, 66, 1, 1, 4, 4, 3, 2, 4, 16, 48, 59, 6, 9, 96, 134, 72, 1, 134, 248, 66,
        1, 13, 4, 46, 22, 44, 79, 112, 101, 110, 83, 83, 76, 32, 71, 101, 110, 101, 114, 97, 116,
        101, 100, 32, 67, 108, 105, 101, 110, 116, 32, 83, 105, 103, 110, 105, 110, 103, 32, 67,
        101, 114, 116, 105, 102, 105, 99, 97, 116, 101, 48, 29, 6, 3, 85, 29, 14, 4, 22, 4, 20,
        212, 245, 104, 154, 123, 54, 252, 169, 220, 40, 62, 47, 12, 123, 72, 185, 189, 219, 17,
        107, 48, 31, 6, 3, 85, 29, 35, 4, 24, 48, 22, 128, 20, 114, 86, 204, 131, 144, 237, 149,
        68, 2, 170, 21, 190, 204, 68, 122, 91, 8, 51, 160, 168, 48, 14, 6, 3, 85, 29, 15, 1, 1,
        255, 4, 4, 3, 2, 7, 128, 48, 22, 6, 3, 85, 29, 37, 1, 1, 255, 4, 12, 48, 10, 6, 8, 43, 6,
        1, 5, 5, 7, 3, 3, 48, 13, 6, 9, 42, 134, 72, 134, 247, 13, 1, 1, 11, 5, 0, 3, 130, 2, 1, 0,
        93, 97, 153, 34, 59, 3, 76, 237, 162, 235, 171, 6, 39, 103, 113, 111, 227, 195, 242, 142,
        181, 199, 192, 44, 202, 3, 112, 101, 33, 162, 32, 148, 96, 64, 238, 170, 240, 23, 109, 63,
        52, 151, 8, 45, 193, 182, 109, 171, 179, 220, 176, 81, 122, 137, 249, 59, 45, 166, 74, 42,
        154, 125, 175, 195, 223, 177, 181, 119, 178, 92, 110, 8, 208, 176, 199, 10, 240, 244, 200,
        27, 37, 180, 97, 196, 38, 18, 54, 220, 235, 48, 159, 68, 221, 232, 133, 10, 117, 234, 35,
        128, 41, 250, 194, 163, 65, 113, 52, 211, 232, 187, 132, 221, 50, 35, 19, 255, 160, 183,
        181, 198, 79, 85, 42, 197, 52, 86, 42, 143, 32, 199, 15, 100, 35, 92, 190, 24, 11, 241, 63,
        51, 96, 44, 90, 82, 28, 74, 116, 239, 94, 154, 238, 39, 47, 215, 210, 216, 170, 190, 44,
        12, 234, 159, 212, 6, 65, 17, 52, 199, 254, 48, 207, 187, 5, 175, 162, 37, 88, 102, 142, 0,
        163, 52, 64, 55, 116, 81, 198, 23, 2, 68, 5, 137, 104, 174, 49, 8, 71, 145, 5, 229, 89, 25,
        42, 165, 44, 177, 75, 36, 201, 74, 101, 107, 158, 57, 51, 99, 52, 177, 208, 47, 228, 10,
        35, 41, 2, 94, 117, 161, 24, 27, 169, 111, 62, 75, 237, 0, 90, 253, 221, 193, 81, 217, 253,
        228, 243, 190, 37, 9, 9, 153, 153, 6, 160, 81, 206, 6, 225, 239, 242, 154, 97, 83, 31, 215,
        21, 196, 131, 9, 156, 95, 229, 94, 151, 110, 27, 68, 76, 238, 67, 52, 176, 104, 214, 220,
        193, 254, 79, 228, 59, 169, 193, 163, 146, 128, 174, 156, 105, 138, 196, 104, 244, 97, 232,
        38, 173, 217, 80, 83, 78, 197, 171, 161, 45, 36, 185, 18, 217, 251, 62, 249, 83, 233, 68,
        238, 253, 56, 225, 131, 37, 192, 69, 221, 244, 72, 82, 129, 213, 223, 167, 151, 145, 255,
        191, 105, 59, 44, 253, 39, 9, 85, 53, 44, 21, 61, 4, 51, 155, 125, 12, 201, 228, 39, 162,
        87, 122, 18, 203, 43, 74, 136, 42, 121, 4, 48, 82, 218, 109, 135, 19, 38, 95, 192, 117,
        220, 168, 246, 157, 182, 221, 63, 255, 133, 178, 49, 238, 230, 142, 228, 188, 169, 121,
        249, 90, 212, 73, 169, 143, 85, 161, 251, 80, 145, 43, 26, 171, 35, 18, 171, 19, 214, 141,
        22, 53, 220, 215, 75, 225, 245, 20, 119, 154, 75, 127, 97, 241, 204, 245, 155, 48, 110, 4,
        180, 142, 36, 216, 36, 109, 48, 202, 150, 99, 91, 129, 110, 203, 66, 82, 86, 101, 166, 140,
        207, 158, 118, 128, 235, 175, 147, 95, 176, 75, 17, 235, 154, 61, 99, 36, 197, 72, 52, 72,
        148, 170, 22, 141, 158, 204, 181, 231, 38, 31, 113, 194, 75, 71, 182, 51, 237, 43, 87, 181,
        120, 48, 4, 65, 140, 75, 93, 22, 170, 78, 84,
    ];
    let cert1 = vec![
        48, 130, 6, 25, 48, 130, 4, 1, 160, 3, 2, 1, 2, 2, 2, 16, 0, 48, 13, 6, 9, 42, 134, 72,
        134, 247, 13, 1, 1, 11, 5, 0, 48, 129, 132, 49, 11, 48, 9, 6, 3, 85, 4, 6, 19, 2, 85, 83,
        49, 11, 48, 9, 6, 3, 85, 4, 8, 12, 2, 68, 69, 49, 14, 48, 12, 6, 3, 85, 4, 7, 12, 5, 68,
        111, 118, 101, 114, 49, 20, 48, 18, 6, 3, 85, 4, 10, 12, 11, 75, 97, 105, 79, 83, 32, 83,
        116, 97, 103, 101, 49, 36, 48, 34, 6, 3, 85, 4, 11, 12, 27, 75, 97, 105, 79, 83, 32, 83,
        116, 97, 103, 101, 32, 83, 105, 103, 110, 105, 110, 103, 32, 83, 101, 114, 118, 105, 99,
        101, 49, 28, 48, 26, 6, 3, 85, 4, 3, 12, 19, 75, 97, 105, 79, 83, 32, 83, 116, 97, 103,
        101, 32, 82, 111, 111, 116, 32, 67, 65, 48, 30, 23, 13, 49, 55, 48, 49, 50, 51, 48, 49, 53,
        52, 53, 48, 90, 23, 13, 50, 55, 48, 49, 50, 49, 48, 49, 53, 52, 53, 48, 90, 48, 116, 49,
        11, 48, 9, 6, 3, 85, 4, 6, 19, 2, 85, 83, 49, 11, 48, 9, 6, 3, 85, 4, 8, 12, 2, 68, 69, 49,
        20, 48, 18, 6, 3, 85, 4, 10, 12, 11, 75, 97, 105, 79, 83, 32, 83, 116, 97, 103, 101, 49,
        36, 48, 34, 6, 3, 85, 4, 11, 12, 27, 75, 97, 105, 79, 83, 32, 83, 116, 97, 103, 101, 32,
        83, 105, 103, 110, 105, 110, 103, 32, 83, 101, 114, 118, 105, 99, 101, 49, 28, 48, 26, 6,
        3, 85, 4, 3, 12, 19, 75, 97, 105, 79, 83, 32, 83, 116, 97, 103, 101, 32, 82, 111, 111, 116,
        32, 67, 65, 48, 130, 2, 34, 48, 13, 6, 9, 42, 134, 72, 134, 247, 13, 1, 1, 1, 5, 0, 3, 130,
        2, 15, 0, 48, 130, 2, 10, 2, 130, 2, 1, 0, 177, 136, 78, 13, 230, 250, 144, 68, 243, 234,
        202, 226, 217, 80, 235, 255, 191, 14, 18, 206, 123, 0, 40, 227, 220, 146, 10, 166, 124, 86,
        110, 183, 137, 116, 58, 63, 10, 55, 35, 124, 193, 223, 106, 147, 187, 151, 74, 99, 165,
        152, 105, 179, 82, 160, 19, 112, 180, 174, 188, 31, 129, 161, 1, 7, 55, 4, 249, 77, 243,
        74, 41, 27, 190, 192, 107, 102, 170, 149, 191, 183, 238, 245, 97, 121, 128, 163, 216, 86,
        136, 244, 46, 106, 112, 226, 139, 3, 142, 133, 81, 205, 30, 66, 181, 181, 24, 224, 6, 21,
        124, 179, 229, 96, 86, 181, 126, 197, 29, 200, 114, 242, 166, 161, 28, 143, 229, 144, 221,
        3, 127, 127, 170, 185, 241, 163, 213, 145, 70, 186, 221, 79, 116, 193, 74, 89, 191, 196,
        203, 249, 158, 129, 195, 150, 50, 67, 2, 131, 138, 52, 190, 237, 143, 140, 17, 202, 189,
        54, 158, 88, 79, 30, 236, 24, 10, 9, 136, 151, 228, 135, 117, 74, 77, 210, 110, 239, 18,
        56, 231, 92, 43, 152, 44, 236, 161, 177, 103, 32, 161, 74, 27, 74, 38, 149, 179, 142, 217,
        248, 206, 33, 209, 235, 184, 209, 255, 30, 44, 7, 175, 170, 5, 146, 44, 49, 193, 115, 18,
        106, 82, 81, 152, 14, 52, 41, 255, 237, 204, 207, 27, 50, 207, 252, 83, 97, 244, 191, 78,
        202, 45, 77, 126, 69, 197, 19, 122, 212, 171, 60, 2, 243, 236, 254, 132, 149, 175, 114, 33,
        45, 190, 94, 210, 34, 53, 1, 248, 15, 9, 4, 6, 132, 250, 103, 24, 170, 96, 136, 158, 38,
        151, 153, 191, 63, 106, 45, 15, 170, 137, 252, 159, 22, 57, 182, 22, 70, 7, 253, 151, 157,
        0, 214, 56, 2, 211, 83, 173, 224, 219, 242, 251, 212, 97, 218, 228, 103, 37, 134, 157, 3,
        70, 143, 11, 186, 94, 97, 183, 210, 45, 198, 197, 196, 212, 149, 20, 253, 7, 2, 142, 59,
        113, 222, 102, 131, 179, 63, 122, 192, 204, 120, 51, 242, 248, 56, 75, 109, 246, 252, 70,
        76, 164, 15, 112, 220, 170, 131, 143, 43, 209, 44, 22, 184, 86, 129, 164, 231, 81, 239,
        146, 55, 161, 28, 31, 113, 94, 26, 104, 36, 1, 75, 35, 159, 40, 53, 176, 89, 153, 222, 10,
        171, 244, 38, 130, 86, 21, 23, 96, 55, 222, 198, 241, 91, 105, 147, 37, 157, 242, 138, 3,
        14, 114, 196, 222, 239, 117, 130, 79, 39, 94, 217, 241, 225, 202, 57, 244, 4, 210, 35, 171,
        199, 155, 15, 216, 225, 86, 241, 116, 118, 237, 212, 130, 55, 108, 143, 113, 154, 85, 20,
        59, 24, 74, 100, 29, 36, 52, 42, 173, 121, 44, 137, 48, 186, 152, 167, 104, 184, 197, 148,
        67, 246, 16, 81, 245, 164, 52, 150, 91, 170, 73, 162, 220, 153, 161, 96, 33, 186, 128, 11,
        178, 40, 243, 155, 226, 105, 104, 167, 2, 3, 1, 0, 1, 163, 129, 163, 48, 129, 160, 48, 17,
        6, 9, 96, 134, 72, 1, 134, 248, 66, 1, 1, 4, 4, 3, 2, 4, 176, 48, 29, 6, 3, 85, 29, 14, 4,
        22, 4, 20, 114, 86, 204, 131, 144, 237, 149, 68, 2, 170, 21, 190, 204, 68, 122, 91, 8, 51,
        160, 168, 48, 31, 6, 3, 85, 29, 35, 4, 24, 48, 22, 128, 20, 140, 183, 191, 13, 208, 211,
        94, 124, 65, 163, 62, 95, 230, 42, 30, 184, 34, 124, 174, 1, 48, 18, 6, 3, 85, 29, 19, 1,
        1, 255, 4, 8, 48, 6, 1, 1, 255, 2, 1, 0, 48, 14, 6, 3, 85, 29, 15, 1, 1, 255, 4, 4, 3, 2,
        1, 134, 48, 39, 6, 3, 85, 29, 37, 4, 32, 48, 30, 6, 8, 43, 6, 1, 5, 5, 7, 3, 2, 6, 8, 43,
        6, 1, 5, 5, 7, 3, 4, 6, 8, 43, 6, 1, 5, 5, 7, 3, 3, 48, 13, 6, 9, 42, 134, 72, 134, 247,
        13, 1, 1, 11, 5, 0, 3, 130, 2, 1, 0, 128, 143, 252, 59, 241, 188, 158, 186, 47, 139, 18,
        178, 33, 33, 146, 68, 121, 99, 188, 69, 188, 232, 67, 175, 116, 164, 65, 227, 121, 100,
        101, 161, 171, 105, 231, 211, 103, 61, 5, 207, 222, 66, 101, 169, 167, 210, 248, 20, 97,
        84, 206, 86, 118, 122, 110, 65, 130, 32, 72, 237, 201, 186, 250, 149, 32, 82, 164, 64, 184,
        45, 154, 78, 115, 151, 64, 117, 229, 101, 120, 100, 248, 158, 92, 8, 227, 253, 239, 142,
        48, 156, 3, 123, 113, 193, 162, 210, 129, 64, 144, 244, 38, 254, 74, 31, 53, 132, 164, 164,
        238, 184, 185, 46, 22, 242, 105, 8, 109, 169, 62, 234, 209, 167, 62, 73, 163, 10, 39, 233,
        201, 220, 239, 106, 98, 245, 79, 199, 90, 207, 53, 129, 42, 78, 8, 159, 69, 182, 46, 143,
        123, 41, 77, 87, 61, 34, 202, 139, 107, 148, 127, 243, 54, 55, 15, 235, 11, 57, 50, 132,
        98, 244, 69, 31, 187, 252, 15, 114, 111, 196, 41, 247, 139, 161, 24, 139, 246, 20, 93, 232,
        135, 71, 42, 128, 24, 148, 215, 237, 61, 193, 179, 222, 58, 70, 124, 211, 142, 172, 44,
        104, 132, 165, 241, 231, 159, 59, 17, 240, 111, 73, 249, 64, 205, 218, 106, 214, 203, 218,
        102, 41, 252, 183, 194, 234, 151, 98, 16, 70, 161, 37, 37, 53, 124, 60, 212, 117, 213, 186,
        162, 251, 8, 150, 152, 164, 115, 24, 167, 253, 79, 251, 198, 231, 48, 221, 164, 251, 227,
        166, 98, 227, 20, 106, 137, 86, 179, 4, 113, 13, 113, 208, 69, 93, 225, 59, 3, 176, 177,
        100, 70, 29, 101, 62, 14, 133, 174, 251, 37, 89, 80, 247, 76, 215, 222, 172, 195, 36, 251,
        233, 94, 168, 195, 205, 42, 129, 221, 224, 251, 242, 224, 233, 48, 51, 149, 16, 227, 138,
        141, 127, 84, 249, 188, 250, 91, 170, 147, 26, 17, 25, 41, 22, 143, 104, 24, 90, 173, 199,
        128, 214, 48, 146, 179, 125, 124, 1, 73, 62, 68, 154, 22, 51, 173, 30, 67, 147, 77, 71, 42,
        106, 93, 90, 237, 99, 192, 185, 12, 49, 242, 247, 110, 82, 223, 91, 10, 184, 127, 220, 68,
        73, 70, 104, 118, 172, 169, 122, 67, 89, 255, 1, 186, 114, 70, 141, 96, 88, 4, 224, 92,
        168, 244, 29, 81, 40, 233, 71, 36, 68, 183, 120, 186, 5, 132, 128, 59, 191, 31, 109, 214,
        20, 209, 105, 177, 120, 149, 192, 82, 212, 220, 179, 15, 33, 5, 226, 227, 179, 223, 219,
        90, 35, 251, 167, 144, 238, 235, 215, 166, 124, 255, 2, 63, 32, 157, 173, 205, 191, 197,
        78, 191, 118, 204, 135, 107, 95, 51, 185, 98, 51, 183, 205, 124, 161, 192, 105, 220, 210,
        211, 64, 85, 0, 65, 188, 249, 155, 21, 64, 89, 134, 142, 225, 151, 144, 144, 140, 200, 196,
        89, 15, 197, 218, 34, 249, 186, 80, 165, 52,
    ];
    let expected_dig = vec![
        106, 230, 32, 43, 153, 61, 228, 241, 26, 222, 78, 191, 111, 66, 110, 85, 144, 70, 188, 149,
    ];

    let rsa_info = parse_rsa(&rsa_raw).unwrap();
    assert_eq!(rsa_info.certs_rsa.len(), 2);
    assert_eq!(rsa_info.certs_rsa[0], cert0);
    assert_eq!(rsa_info.certs_rsa[1], cert1);
    assert_eq!(rsa_info.sf_dig, expected_dig);

    let mut rsa_file = File::open("test-fixtures/mozilla.rsa").unwrap();
    let mut rsa_raw: Vec<u8> = Vec::new();
    rsa_file.read_to_end(&mut rsa_raw).unwrap();
    let rsa_info = parse_rsa(&rsa_raw).unwrap();
    assert_eq!(rsa_info.certs_rsa.len(), 2);
}

#[test]
fn test_other_rsa() {
    use std::fs::File;
    use std::io::Read;

    // android
    // SET {
    //     SEQUENCE {
    //        INTEGER 0x01 (1 decimal){...}
    //        SEQUENCE {...}
    //        SEQUENCE {...}
    //        OCTETSTRING 3588518...
    //     }
    // }
    // whereas ours
    // SET {
    //     SEQUENCE {
    //        INTEGER 0x01 (1 decimal) {...}
    //        SEQUENCE {...}
    //        SEQUENCE {...}
    //        [0] {...}
    //        SEQUENCE {...}
    //        OCTETSTRING 3588518...
    //     }
    // }
    let mut rsa_file = File::open("test-fixtures/android.rsa").unwrap();
    let mut rsa_raw: Vec<u8> = Vec::new();
    rsa_file.read_to_end(&mut rsa_raw).unwrap();
    let result = parse_rsa(&rsa_raw);
    assert!(result.is_err());
}


#[test]
fn test_check_expiry() {
    let start = "Jul  1 17:17:40 2020 GMT".into();
    let end = "Jan 14 07:51:52 2017 GMT".into();
    match check_expiry(start, end) {
        Ok(_) => assert!(false),
        Err(_) => assert!(true),
    }

    let start = "Jan 14 07:51:52 2017 GMT".into();
    let end = "Jul  1 17:17:40 2018 GMT".into();
    match check_expiry(start, end) {
        Ok(_) => assert!(false),
        Err(_) => assert!(true),
    }

    let start = "Jan 14 07:51:52 2017 GMT".into();
    let end = "Jul  1 17:17:40 2021 GMT".into();
    match check_expiry(start, end) {
        Ok(_) => assert!(true),
        Err(_) => assert!(false),
    }

    let start = "randomstring123".into();
    let end = "".into();
    match check_expiry(start, end) {
        Ok(_) => assert!(false),
        Err(_) => assert!(true),
    }

    let start = "Feb 19 00:00:00 1984 GMT".into();
    let end = "Mar  21 11:11:11 2084 GMT".into();
    match check_expiry(start, end) {
        Ok(_) => assert!(true),
        Err(_) => assert!(false),
    }
}