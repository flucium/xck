#[test]
fn ed25519_sign() {
    const TEST_PRIVATE_KEY: [u8; 32] = [
        68, 87, 109, 156, 131, 213, 127, 10, 63, 10, 61, 181, 243, 100, 121, 102, 53, 62, 215, 212,
        67, 223, 238, 9, 34, 39, 44, 10, 51, 2, 56, 96,
    ];

    // hello = [104, 101, 108, 108, 111]
    const TEST_MESSAGE: [u8; 5] = [104, 101, 108, 108, 111];

    const TEST_SIGNATURE: [u8; 64] = [
        83, 20, 131, 218, 63, 174, 163, 255, 37, 122, 54, 8, 232, 117, 239, 45, 201, 70, 101, 142,
        217, 147, 210, 94, 135, 222, 113, 244, 162, 251, 115, 56, 222, 63, 84, 150, 241, 44, 243,
        138, 57, 64, 22, 0, 105, 198, 207, 240, 52, 170, 213, 157, 88, 49, 176, 187, 42, 12, 53,
        79, 41, 22, 42, 3,
    ];

    assert_eq!(
        xck::asymmetric::ed25519_sign(&TEST_PRIVATE_KEY, &TEST_MESSAGE).unwrap(),
        TEST_SIGNATURE
    );
}

#[test]
fn ed25519_verify() {
    const TEST_PUBLIC_KEY: [u8; 32] = [
        8, 230, 98, 51, 57, 27, 17, 99, 190, 212, 187, 167, 138, 235, 172, 89, 144, 104, 152, 174,
        242, 25, 168, 132, 53, 182, 187, 232, 142, 1, 1, 187,
    ];

    // hello = [104, 101, 108, 108, 111]
    const TEST_MESSAGE: [u8; 5] = [104, 101, 108, 108, 111];

    const TEST_SIGNATURE: [u8; 64] = [
        83, 20, 131, 218, 63, 174, 163, 255, 37, 122, 54, 8, 232, 117, 239, 45, 201, 70, 101, 142,
        217, 147, 210, 94, 135, 222, 113, 244, 162, 251, 115, 56, 222, 63, 84, 150, 241, 44, 243,
        138, 57, 64, 22, 0, 105, 198, 207, 240, 52, 170, 213, 157, 88, 49, 176, 187, 42, 12, 53,
        79, 41, 22, 42, 3,
    ];

    assert_eq!(
        xck::asymmetric::ed25519_verify(&TEST_PUBLIC_KEY, &TEST_MESSAGE, &TEST_SIGNATURE).is_ok(),
        true
    );
}

#[test]
fn ed25519() {
    // hello = [104, 101, 108, 108, 111]
    const TEST_MESSAGE: [u8; 5] = [104, 101, 108, 108, 111];

    let (private_key, public_key) = xck::asymmetric::ed25519_gen_keypair();

    let signature = xck::asymmetric::ed25519_sign(&private_key, &TEST_MESSAGE).unwrap();

    let is_ok = xck::asymmetric::ed25519_verify(&public_key, &TEST_MESSAGE, &signature).is_ok();

    assert_eq!(is_ok, true);
}

#[test]
fn x25519_diffie_hellman() {
    let alice_private_key: [u8; 32] = [
        45, 162, 45, 39, 64, 231, 153, 194, 122, 98, 107, 62, 92, 11, 143, 141, 125, 225, 86, 3,
        112, 134, 89, 217, 7, 69, 94, 221, 58, 144, 165, 180,
    ];

    let alice_public_key: [u8; 32] = [
        199, 120, 240, 236, 92, 200, 1, 149, 127, 9, 188, 222, 135, 251, 137, 2, 128, 66, 72, 94,
        134, 137, 212, 88, 80, 229, 179, 223, 163, 149, 187, 10,
    ];

    let bob_private_key: [u8; 32] = [
        19, 35, 157, 143, 14, 43, 61, 168, 28, 46, 239, 166, 39, 199, 173, 205, 230, 61, 131, 21,
        101, 223, 149, 130, 156, 244, 213, 8, 164, 193, 89, 117,
    ];

    let bob_public_key: [u8; 32] = [
        45, 63, 45, 131, 40, 198, 223, 245, 64, 24, 44, 61, 24, 246, 22, 106, 147, 11, 134, 240,
        57, 15, 170, 207, 215, 72, 45, 177, 146, 142, 77, 55,
    ];

    let alice_shared: [u8; 32] =
        xck::asymmetric::x25519_diffie_hellman(&alice_private_key, &bob_public_key);

    let bob_shared: [u8; 32] =
        xck::asymmetric::x25519_diffie_hellman(&bob_private_key, &alice_public_key);

    assert_eq!(alice_shared, bob_shared);
}

#[test]
fn x25519() {
    let (alice_private_key, alice_public_key) = xck::asymmetric::x25519_gen_keypair();

    let (bob_private_key, bob_public_key) = xck::asymmetric::x25519_gen_keypair();

    let alice_shared = xck::asymmetric::x25519_diffie_hellman(&alice_private_key, &bob_public_key);

    let bob_shared = xck::asymmetric::x25519_diffie_hellman(&bob_private_key, &alice_public_key);

    assert_eq!(alice_shared, bob_shared);
}
