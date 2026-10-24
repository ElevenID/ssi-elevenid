use k256::elliptic_curve::sec1::ToSec1Point;
use std::borrow::Cow;

use crate::{Codec, Error, SECP256K1_PUB};

impl Codec for k256::PublicKey {
    const CODEC: u64 = SECP256K1_PUB;

    fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        Self::from_sec1_bytes(bytes).map_err(|_| Error::InvalidData)
    }

    fn to_bytes(&'_ self) -> Cow<'_, [u8]> {
        Cow::Owned(self.to_sec1_point(true).as_bytes().to_vec())
    }
}
