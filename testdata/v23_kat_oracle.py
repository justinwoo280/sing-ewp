#!/usr/bin/env python3
"""Independent KAT oracle for EWP/v2.3.

Recomputes every v2.3 cryptographic step with PyNaCl / hashlib / hmac only,
so the Go implementation is verified against a second, independent stack.
Generates testdata/v23_vectors.json; the Go test TestV23CryptoKAT then
compares against the frozen values. Never edit the JSON by hand.
"""
import hashlib, hmac, json, sys

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives import serialization
except ImportError:
    sys.exit("pip install cryptography")

LABEL = "ewp/v2.3"

SERVER_ID = "v23-kat"
ROUTE_EPOCH = 0
UUID = bytes.fromhex("11111111222233334444555555555555")
COOKIE_KEY = bytes(range(32))
SIGNING_SEED = bytes([0x5a] * 32)
CLIENT_NONCE = bytes(range(16))
SERVER_NONCE = bytes(range(16, 32))
EXPIRES_AT = 1_700_000_600
SOURCE = "203.0.113.7:51000"
OUTER_KEY_ID = bytes([0x01] * 8)
OUTER_PUB = bytes([0x42] * 32)
NOT_BEFORE = EXPIRES_AT - 3600
NOT_AFTER = EXPIRES_AT + 3600


def route_tag(uuid, server_id, epoch):
    psk = hashlib.sha256(uuid).digest()
    m = hmac.new(psk, digestmod=hashlib.sha256)
    m.update(f"{LABEL}/route".encode())
    m.update(server_id.encode())
    m.update(epoch.to_bytes(8, "big"))
    return m.digest()[:16]


def cookie(cookie_key, server_id, source, client_nonce, server_nonce, expires_at, key_id):
    m = hmac.new(cookie_key, digestmod=hashlib.sha256)
    m.update(f"{LABEL}/cookie".encode())
    m.update(server_id.encode())
    m.update(source.encode())
    m.update(client_nonce)
    m.update(server_nonce)
    m.update(expires_at.to_bytes(8, "big"))
    m.update(key_id)
    return m.digest()[:32]


def transcript(label, *parts):
    h = hashlib.sha256()
    h.update(label.encode())
    for p in parts:
        h.update(len(p).to_bytes(4, "big"))
        h.update(p)
    return h.digest()


def outer_key_sig_payload(server_id, key_id, not_before, not_after, pub):
    h = hashlib.sha256()
    h.update(f"{LABEL}/outer-key".encode())
    h.update(server_id.encode())
    h.update(key_id)
    h.update(not_before.to_bytes(8, "big"))
    h.update(not_after.to_bytes(8, "big"))
    h.update(pub)
    return h.digest()


def main():
    rt = route_tag(UUID, SERVER_ID, ROUTE_EPOCH)
    client_init = CLIENT_NONCE + rt

    t_ci = transcript(f"{LABEL}/t-ci", client_init)

    ck = cookie(COOKIE_KEY, SERVER_ID, SOURCE, CLIENT_NONCE, SERVER_NONCE, EXPIRES_AT, OUTER_KEY_ID)

    hello_retry = (
        CLIENT_NONCE + SERVER_NONCE + EXPIRES_AT.to_bytes(8, "big") + ck
        + OUTER_KEY_ID + NOT_BEFORE.to_bytes(8, "big") + NOT_AFTER.to_bytes(8, "big")
        + OUTER_PUB + bytes(64)  # signature placeholder for transcript
    )

    sk = Ed25519PrivateKey.from_private_bytes(SIGNING_SEED)
    sig = sk.sign(outer_key_sig_payload(SERVER_ID, OUTER_KEY_ID, NOT_BEFORE, NOT_AFTER, OUTER_PUB))
    hello_retry = hello_retry[:-64] + sig

    t_hr = transcript(f"{LABEL}/t-hr", t_ci, hello_retry)

    vectors = {
        "server_id": SERVER_ID,
        "route_epoch": ROUTE_EPOCH,
        "uuid_hex": UUID.hex(),
        "cookie_key_hex": COOKIE_KEY.hex(),
        "signing_seed_hex": SIGNING_SEED.hex(),
        "client_nonce_hex": CLIENT_NONCE.hex(),
        "server_nonce_hex": SERVER_NONCE.hex(),
        "expires_at": EXPIRES_AT,
        "source": SOURCE,
        "outer_key_id_hex": OUTER_KEY_ID.hex(),
        "outer_pub_hex": OUTER_PUB.hex(),
        "route_tag_hex": rt.hex(),
        "cookie_hex": ck.hex(),
        "client_init_hex": client_init.hex(),
        "hello_retry_hex": hello_retry.hex(),
        "t_ci_hex": t_ci.hex(),
        "t_hr_hex": t_hr.hex(),
        "outer_key_sig_hex": sig.hex(),
    }
    with open("testdata/v23_vectors.json", "w") as f:
        json.dump(vectors, f, indent=2)
    print("wrote testdata/v23_vectors.json")


if __name__ == "__main__":
    main()
