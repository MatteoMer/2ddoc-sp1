use chrono::{Days, NaiveDate};
use image::{DynamicImage, GenericImageView};
use rxing::{
    common::HybridBinarizer, datamatrix::DataMatrixReader, BinaryBitmap,
    BufferedImageLuminanceSource, Reader,
};

use p256::{
    ecdsa::{signature::Verifier, Signature, VerifyingKey},
    EncodedPoint,
};
use std::str;

#[derive(Debug)]
pub struct DocHeader {
    version: u8,
    ca_id: String,
    cert_id: String,
    emit_date: NaiveDate,
    sign_date: NaiveDate,
    doc_type_id: String,
    perimeter_id: u32,
    country_id: String,
}

#[derive(Debug)]
pub enum DocError {
    UnsupportedVersion,
    InvalidFormat,
    DateParseError,
    Utf8Error,
}

impl DocHeader {
    pub fn from_code(code: &[u8]) -> Result<Self, DocError> {
        if let Ok(text) = str::from_utf8(code) {
            if text.starts_with("DC") {
                println!("here");
                return Self::from_ascii(text);
            }
        }

        println!("here");
        if code[0] == 0xdc {
            return Self::from_binary(code);
        }

        println!("here2");
        Err(DocError::InvalidFormat)
    }

    pub fn from_ascii(code: &str) -> Result<Self, DocError> {
        if code.len() < 24 {
            return Err(DocError::InvalidFormat);
        }

        let version = code[2..4]
            .parse::<u8>()
            .map_err(|_| DocError::InvalidFormat)?;

        if !(1..=4).contains(&version) {
            return Err(DocError::UnsupportedVersion);
        }

        let ca_id = code[4..8].to_string();
        let cert_id = code[8..12].to_string();
        let emit_date = Self::parse_date(&code[12..16]).map_err(|_| DocError::DateParseError)?;
        let sign_date = Self::parse_date(&code[16..20]).map_err(|_| DocError::DateParseError)?;
        let doc_type_id = code[20..22].to_string();
        let perimeter_id = if version >= 3 {
            code[22..24].parse::<u32>().unwrap_or(1)
        } else {
            1
        };
        let country_id = if version >= 4 {
            code[24..26].to_string()
        } else {
            "FR".to_string()
        };

        Ok(DocHeader {
            version,
            ca_id,
            cert_id,
            emit_date,
            sign_date,
            doc_type_id,
            perimeter_id,
            country_id,
        })
    }

    pub fn from_binary(code: &[u8]) -> Result<Self, DocError> {
        if code.len() < 19 {
            return Err(DocError::InvalidFormat);
        }

        let version = code[1];
        if version != 4 {
            return Err(DocError::UnsupportedVersion);
        }

        // Note: Actual C40 parsing implementation would be needed here
        let country_id = String::from_utf8(code[2..4].to_vec()).map_err(|_| DocError::Utf8Error)?;

        let ca_cert = String::from_utf8(code[4..10].to_vec()).map_err(|_| DocError::Utf8Error)?;
        let ca_id = ca_cert[0..4].to_string();
        let cert_id = ca_cert[4..].to_string();

        let emit_date =
            Self::parse_binary_date(&code[10..13]).map_err(|_| DocError::DateParseError)?;
        let sign_date =
            Self::parse_binary_date(&code[13..16]).map_err(|_| DocError::DateParseError)?;

        let doc_type_id = code[16].to_string();
        let perimeter_id = u32::from_be_bytes([0, 0, code[17], code[18]]);

        Ok(DocHeader {
            version,
            ca_id,
            cert_id,
            emit_date,
            sign_date,
            doc_type_id,
            perimeter_id,
            country_id,
        })
    }

    // Helper function to parse dates in the format used in ASCII mode
    fn parse_date(date_str: &str) -> Result<NaiveDate, chrono::ParseError> {
        // Implementation would depend on your date format
        // This is a placeholder - adjust according to your actual date format
        let days = u32::from_str_radix(date_str, 16).unwrap();

        // Start date: January 1st, 2000
        let base_date = NaiveDate::from_ymd_opt(2000, 1, 1).unwrap();

        // Add the number of days
        Ok(base_date.checked_add_days(Days::new(days as u64)).unwrap())
    }

    // Helper function to parse dates in binary format
    fn parse_binary_date(date_bytes: &[u8]) -> Result<NaiveDate, chrono::ParseError> {
        // Implementation would depend on your binary date format
        // This is a placeholder - adjust according to your actual binary date format
        let year = 2000 + date_bytes[0] as i32;
        let month = date_bytes[1] as u32;
        let day = date_bytes[2] as u32;
        Ok(NaiveDate::from_ymd_opt(year, month, day).unwrap())
    }
}

pub struct TwoDoc {
    pub header: DocHeader,
    pub message: String,
    pub signature: Vec<u8>,
    pub signed_data: Vec<u8>,
}

#[derive(Debug)]
pub enum TwoDocError {
    UnsupportedBinaryCode,
    InvalidFormat,
    HeaderParseError,
    Base32DecodeError,
    MessageParseError,
    InvalidVersion,
    TooShort,
}

#[derive(Debug)]
pub enum KeyError {
    DatabaseError(String),
    NoKeyFound,
    #[cfg(not(feature = "sqlite"))]
    NotImplemented,
}

impl TwoDoc {
    // Helper function to get header length based on version
    fn get_header_length(version: &str) -> Result<usize, TwoDocError> {
        match version {
            "01" | "02" => Ok(22),
            "03" => Ok(24),
            "04" => Ok(26),
            _ => Err(TwoDocError::InvalidVersion),
        }
    }

    pub fn from_image(path: &str) -> Result<Self, TwoDocError> {
        let img = image::open(path).unwrap();

        // Use default decoder
        let mut decoder = DataMatrixReader::default();

        let mut image = BinaryBitmap::new(HybridBinarizer::new(BufferedImageLuminanceSource::new(
            image::open(path).unwrap(),
        )));

        let results = decoder.decode(&mut image).unwrap();

        //let header = DocHeader::from_code(results.getRawBytes()).unwrap();
        let doc = TwoDoc::from_code(results.getText()).unwrap();
        let header = &doc.header;

        println!("version: {}\nca_id: {}\ncert_id: {}\nemit_date: {}\nsign_date: {}\ndoc_type_id: {}\nperimeter_id: {}\ncountry_id: {}", header.version, header.ca_id, header.cert_id, header.emit_date, header.sign_date, header.doc_type_id, header.perimeter_id, header.country_id);
        println!("signed_data: {}", str::from_utf8(&doc.signed_data).unwrap());

        Ok(doc)
    }

    pub fn from_code(doc: &str) -> Result<Self, TwoDocError> {
        // Check minimum length and DC prefix
        if doc.len() < 4 || !doc.starts_with("DC") {
            return Err(TwoDocError::TooShort);
        }

        // Get version from the DC prefix
        let version = &doc[2..4];

        // Determine header length based on version
        let header_length = Self::get_header_length(version)?;

        // Ensure document is long enough to contain the header
        if doc.len() < header_length {
            return Err(TwoDocError::TooShort);
        }

        // Now we can safely parse the header knowing its length
        let header = DocHeader::from_ascii(doc).unwrap();

        // Split document after the known header length
        let data_portion = doc.get(header_length..).ok_or(TwoDocError::InvalidFormat)?;

        // Split data and signature at ASCII unit separator (0x1F)
        let (data, sign) = data_portion
            .split_once('\x1f')
            .ok_or(TwoDocError::InvalidFormat)?;

        // Decode base32 signature (adding padding if needed)
        let mut padded_sign = sign.to_string();
        while padded_sign.len() % 8 != 0 {
            padded_sign.push('=');
        }

        let signature = base32::decode(base32::Alphabet::Rfc4648 { padding: true }, &padded_sign)
            .ok_or(TwoDocError::Base32DecodeError)?;

        // Parse C40 message
        //let message = C40Message::from_code(header.perimeter_id, data)
        //   .map_err(|_| TwoDocError::MessageParseError)?;

        // Construct signed data
        let signed_data = format!("{}{}", &doc[..header_length], data).into_bytes();

        if header.doc_type_id != "04" {
            panic!("[provable-2ddoc] not a tax report");
        }

        Ok(TwoDoc {
            header,
            message: "".to_string(),
            signature,
            signed_data,
        })
    }

    #[cfg(feature = "sqlite")]
    pub fn get_public_key(header: &DocHeader) -> Result<Vec<u8>, KeyError> {
        use rusqlite::Connection;

        // Attempt to connect to the SQLite database
        let conn = Connection::open("certificates.db").map_err(|e| {
            KeyError::DatabaseError(format!("Failed to connect to database: {}", e))
        })?;

        // Query to find the matching certificate
        let query = "
            SELECT c.public_key
            FROM certificates c
            JOIN providers p ON c.provider_id = p.id
            WHERE c.issuer_name LIKE ?1 
            AND c.subject_name LIKE ?2
            -- Get the most recent valid certificate
            AND c.not_valid_after >= datetime('now')
            AND c.not_valid_before <= datetime('now')
            ORDER BY c.not_valid_after DESC
            LIMIT 1
        ";

        conn.query_row(
            query,
            &[
                &format!("%{}%", header.ca_id),
                &format!("%{}%", header.cert_id),
            ],
            |row| row.get::<_, Vec<u8>>(0),
        )
        .map_err(|e| match e {
            rusqlite::Error::QueryReturnedNoRows => KeyError::NoKeyFound,
            _ => KeyError::DatabaseError(format!("Database error: {}", e)),
        })
    }

    // Provide a default implementation when sqlite feature is not enabled
    #[cfg(not(feature = "sqlite"))]
    pub fn get_public_key(_header: &DocHeader) -> Result<Vec<u8>, KeyError> {
        Err(KeyError::NotImplemented)
    }

    pub fn verify_signature(signed_data: &[u8], signature: &[u8], public_key: &[u8]) -> bool {
        println!("[verif-sign] starting verification");
        // Try to parse the public key from bytes
        let encoded_point = match EncodedPoint::from_bytes(public_key) {
            Ok(point) => point,
            Err(_) => return false,
        };

        println!("[verif-sign] point encoded");

        // Create a verifying key from the encoded point
        let verifying_key = match VerifyingKey::from_encoded_point(&encoded_point) {
            Ok(key) => key,
            Err(_) => return false,
        };

        println!("[verif-sign] vkey processed");

        println!("[verif-sign {:?}]", public_key);
        // Parse the signature from bytes
        let signature = match Signature::from_der(signature) {
            Ok(sig) => sig,
            Err(_) => return false,
        };

        println!("[verif-sign] signature processed");

        // Verify the signature
        verifying_key.verify(signed_data, &signature).is_ok()
    }
}
