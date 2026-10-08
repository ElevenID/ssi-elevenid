//! DER (Distinguished Encoding Rules) and ASN.1
//!
//! This module provides various cryptographic data structures and their [ASN.1] (de)serialization
//! using [simple_asn1].
//!
//! [ASN.1]: https://www.iso.org/standard/81420.html "ISO/IEC 8825-1:2021"
//! [simple_asn1]: https://crates.io/crates/simple_asn1
//!
// http://luca.ntop.org/Teaching/Appunti/asn1.html
// https://tls.mbed.org/kb/cryptography/asn1-key-structures-in-der-and-pem
// https://en.wikipedia.org/wiki/Distinguished_Encoding_Rules#BER_encoding
// https://serde.rs/impl-serializer.html
// ISO/IEC 8825-1:2015 (E)
// https://tools.ietf.org/html/rfc8017#page-55
// https://tools.ietf.org/html/rfc8410

use num_bigint::BigInt;
#[cfg(test)]
use num_bigint::Sign;
#[cfg(test)]
use simple_asn1::der_encode;
use simple_asn1::{ASN1Block, ASN1Class, ASN1DecodeErr, ASN1EncodeErr, FromASN1, ToASN1};

/// RSA public key for ASN.1 encoding, as specified in [RFC 8017].
///
/// [RFC 8017]: https://datatracker.ietf.org/doc/html/rfc8017#appendix-A.1.1 "RFC 8017 PKCS #1 v2.2 - A.1.1. RSA Public Key Syntax"
#[derive(Debug, Clone)]
// https://datatracker.ietf.org/doc/html/rfc3447#appendix-A.1.1
pub struct RSAPublicKey {
    pub modulus: Integer,
    pub public_exponent: Integer,
}

/// Ed25519 public key for ASN.1 encoding, as specified in [RFC 8410].
///
/// [RFC 8410]: https://datatracker.ietf.org/doc/html/rfc8410#section-10.1 "RFC 8410 Safe Curves for X.509 - 10.1. Example Ed25519 Public Key"
#[derive(Debug, Clone)]
pub struct Ed25519PublicKey {
    pub public_key: BitString,
}

#[derive(Debug, Clone)]
/// An integer value, for encoding in [ASN.1][ITU X.690]
///
/// [ITU X.690]: https://www.itu.int/rec/T-REC-X.690-202102-I/en
pub struct Integer(pub BigInt);

#[derive(Debug, Clone)]
// TODO: support bitstrings not bytes-aligned
/// A bitstring from [ASN.1][ITU X.690]
///
/// Note: only byte-aligned bitstrings are supported.
///
/// [ITU X.690]: https://www.itu.int/rec/T-REC-X.690-202102-I/en
pub struct BitString(pub Vec<u8>);

impl ToASN1 for RSAPublicKey {
    type Error = ASN1EncodeErr;
    fn to_asn1_class(&self, class: ASN1Class) -> Result<Vec<ASN1Block>, Self::Error> {
        Ok(vec![ASN1Block::Sequence(
            0,
            [
                self.modulus.to_asn1_class(class)?,
                self.public_exponent.to_asn1_class(class)?,
            ]
            .concat(),
        )])
    }
}

#[derive(thiserror::Error, Debug)]
pub enum RSAPublicKeyFromASN1Error {
    #[error("Expected single sequence")]
    ExpectedSingleSequence,
    #[error("Expected two integers")]
    ExpectedTwoIntegers,
    #[error("ASN1 decoding error: {0:?}")]
    ASN1Decode(#[from] ASN1DecodeErr),
}

impl FromASN1 for RSAPublicKey {
    type Error = RSAPublicKeyFromASN1Error;
    fn from_asn1(v: &[ASN1Block]) -> Result<(Self, &[ASN1Block]), Self::Error> {
        let vec = match v {
            [ASN1Block::Sequence(_, vec)] => vec,
            _ => return Err(RSAPublicKeyFromASN1Error::ExpectedSingleSequence),
        };
        let (n, e) = match vec.as_slice() {
            [ASN1Block::Integer(_, n), ASN1Block::Integer(_, e)] => (n, e),
            _ => return Err(RSAPublicKeyFromASN1Error::ExpectedTwoIntegers),
        };
        let pk = Self {
            modulus: Integer(n.clone()),
            public_exponent: Integer(e.clone()),
        };
        Ok((pk, &[]))
    }
}

impl ToASN1 for Ed25519PublicKey {
    type Error = ASN1EncodeErr;
    fn to_asn1_class(&self, class: ASN1Class) -> Result<Vec<ASN1Block>, Self::Error> {
        Ok(vec![ASN1Block::Sequence(
            0,
            self.public_key.to_asn1_class(class)?,
        )])
    }
}

impl ToASN1 for Integer {
    type Error = ASN1EncodeErr;
    fn to_asn1_class(&self, _: ASN1Class) -> Result<Vec<ASN1Block>, Self::Error> {
        Ok(vec![ASN1Block::Integer(0, self.0.clone())])
    }
}

impl ToASN1 for BitString {
    type Error = ASN1EncodeErr;
    fn to_asn1_class(&self, _: ASN1Class) -> Result<Vec<ASN1Block>, Self::Error> {
        Ok(vec![ASN1Block::BitString(0, 0, self.0.clone())])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_integer() {
        let integer = Integer(BigInt::new(Sign::Plus, vec![5]));
        // 0x02: Integer type
        // 0x01: Content length of one byte
        // 0x05: The integer 5
        let expected = vec![0x02, 0x01, 0x05];
        let der = der_encode(&integer).unwrap();
        assert_eq!(der, expected);
    }
}
