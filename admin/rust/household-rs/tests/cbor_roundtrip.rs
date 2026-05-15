use household_rs::cbor::{from_canonical_slice, to_canonical_vec};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
struct Tiny {
    a: u32,
    b: String,
}

#[test]
fn round_trip_tiny() {
    let v = Tiny {
        a: 7,
        b: "hello".into(),
    };
    let bytes = to_canonical_vec(&v).unwrap();
    let back: Tiny = from_canonical_slice(&bytes).unwrap();
    assert_eq!(v, back);
}

#[test]
fn re_encode_byte_equal() {
    let v = Tiny {
        a: 12345,
        b: "world".into(),
    };
    let a = to_canonical_vec(&v).unwrap();
    let parsed: Tiny = from_canonical_slice(&a).unwrap();
    let b = to_canonical_vec(&parsed).unwrap();
    assert_eq!(a, b);
}

#[derive(Serialize)]
struct NonCanonicalDeclarationOrder {
    aa: u8,
    b: u8,
}

#[test]
fn map_keys_are_rfc8949_sorted() {
    let bytes = to_canonical_vec(&NonCanonicalDeclarationOrder { aa: 1, b: 2 }).unwrap();
    assert_eq!(
        bytes,
        vec![
            0xa2, // map(2)
            0x61, b'b', 0x02, // "b" sorts before "aa" by encoded key length
            0x62, b'a', b'a', 0x01,
        ]
    );
}

#[test]
fn map_keys_sort_by_encoded_bytes_not_length_first() {
    use ciborium::value::{Integer, Value};

    let value = Value::Map(vec![
        (Value::Text(String::new()), Value::Integer(Integer::from(1))),
        (
            Value::Integer(Integer::from(24)),
            Value::Integer(Integer::from(2)),
        ),
    ]);

    let bytes = to_canonical_vec(&value).unwrap();
    assert_eq!(
        bytes,
        vec![
            0xa2, // map(2)
            0x18, 0x18, 0x02, // uint(24) sorts before text("") bytewise
            0x60, 0x01, // text("")
        ]
    );
}
