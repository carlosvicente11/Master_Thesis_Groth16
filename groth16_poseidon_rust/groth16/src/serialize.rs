use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Compress, Validate};
use ark_std::vec::Vec;

pub fn to_bytes_compressed<T: CanonicalSerialize>(obj: &T) -> Vec<u8> {
    let mut out = Vec::new();
    obj.serialize_with_mode(&mut out, Compress::Yes)
        .expect("serialize");
    out
}

pub fn from_bytes_compressed<T: CanonicalDeserialize>(bytes: &[u8]) -> T {
    T::deserialize_with_mode(bytes, Compress::Yes, Validate::Yes).expect("deserialize")
}
