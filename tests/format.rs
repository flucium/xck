#[test]
fn to_base64() {
    const TEST_B64_STRING: &str = "aGVsbG8=";

    const TEST_BYTES: [u8; 5] = [104, 101, 108, 108, 111];

    assert_eq!(
        xck::format::to_base64(&TEST_BYTES).unwrap(),
        TEST_B64_STRING
    );
}

#[test]
fn from_base64() {
    const TEST_BYTES: [u8; 5] = [104, 101, 108, 108, 111];

    const TEST_B64_STRING: &str = "aGVsbG8=";

    assert_eq!(
        xck::format::from_base64(&TEST_B64_STRING).unwrap(),
        TEST_BYTES
    );
}

#[test]
fn to_hex() {
    const TEST_BYTES: [u8; 5] = [104, 101, 108, 108, 111];
    
    const TEST_HEX_STRING:&str="68656c6c6f";

    assert_eq!(
        xck::format::to_hex(&TEST_BYTES),
        TEST_HEX_STRING
    );
}

#[test]
fn from_hex() {
    const TEST_BYTES: [u8; 5] = [104, 101, 108, 108, 111];
    
    const TEST_HEX_STRING:&str="68656c6c6f";

    assert_eq!(
        xck::format::from_hex(TEST_HEX_STRING),
        TEST_BYTES
    );
}
