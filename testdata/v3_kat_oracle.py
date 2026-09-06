#!/usr/bin/env python3
"""
EWP/v3 Cryptographic KAT Oracle

Independent implementation using Python + cryptography library.
This oracle MUST NOT import or depend on the Go sing-ewp package.

Purpose: Verify that sing-ewp v3 cryptographic operations produce
         the exact expected output for fixed test vectors.
         
Reference: EWP_V3_HANDSHAKE_DESIGN.md, EWP_V3_RECORDS.md

Dependencies: pip install cryptography
"""

import json
import hmac
import hashlib
import struct
from typing import Tuple
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand


def v3_domain(label: str, *parts: bytes) -> bytes:
    """Length-delimited domain separation as per v3 encoding."""
    out = bytearray()
    def append_part(part: bytes):
        out.extend(struct.pack('>I', len(part)))
        out.extend(part)
    
    append_part(label.encode('utf-8'))
    for part in parts:
        append_part(part)
    return bytes(out)


def v3_hash(label: str, *parts: bytes) -> bytes:
    """SHA-256 hash with domain separation."""
    return hashlib.sha256(v3_domain(label, *parts)).digest()


def v3_hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    """HKDF Extract is HMAC-SHA-256(salt, ikm)."""
    return hmac.new(salt, ikm, hashlib.sha256).digest()


def v3_credential_prk(credential: bytes, listener_context: dict) -> bytes:
    """Derive credential PRK from KAuth and listener context.
    
    EWP_V3_HANDSHAKE_DESIGN.md Key Schedule step 1.
    """
    version = struct.pack('>H', listener_context['version'])
    suite = struct.pack('>H', listener_context['suite'])
    server_id = listener_context['server_id'].encode('utf-8')
    scope = listener_context['deployment_scope'].encode('utf-8')
    
    salt = v3_hash(
        'ewp/v3/credential-salt',
        version, suite, server_id, scope
    )
    
    return v3_hkdf_extract(salt, credential)


def v3_expand(prk: bytes, label: str, listener: dict, transcript: bytes,
              sender: str, receiver: str, direction: str, epoch: int,
              length: int) -> bytes:
    """Transcript-bound HKDF expand."""
    version = struct.pack('>H', listener['version'])
    suite = struct.pack('>H', listener['suite'])
    server_id = listener['server_id'].encode('utf-8')
    scope = listener['deployment_scope'].encode('utf-8')
    
    info = v3_domain(
        'ewp/v3/expand',
        label.encode('utf-8'),
        version, suite, server_id, scope,
        transcript,
        sender.encode('utf-8'),
        receiver.encode('utf-8'),
        direction.encode('utf-8'),
        struct.pack('>Q', epoch)
    )
    
    return HKDFExpand(
        algorithm=hashes.SHA256(),
        length=length,
        info=info
    ).derive(prk)


def v3_outer_prk(listener: dict, credential_prk: bytes, outer_ikm: bytes,
                 t_init: bytes, bundle_digest: bytes,
                 client_hello_header: bytes) -> bytes:
    """Derive outer PRK for ClientHello encryption."""
    salt = v3_hash(
        'ewp/v3/outer-salt',
        t_init, bundle_digest, client_hello_header
    )
    
    # Length-delimited IKM
    ikm = bytearray()
    ikm.extend(struct.pack('>I', len(outer_ikm)))
    ikm.extend(outer_ikm)
    ikm.extend(struct.pack('>I', len(credential_prk)))
    ikm.extend(credential_prk)
    
    return v3_hkdf_extract(salt, bytes(ikm))


def v3_server_hello_prk(listener: dict, credential_prk: bytes,
                        outer_prk: bytes, data_ikm: bytes,
                        t_client_hello: bytes,
                        server_hello_header: bytes) -> bytes:
    """Derive server hello PRK."""
    salt = v3_hash(
        'ewp/v3/server-hello-salt',
        t_client_hello, server_hello_header
    )
    
    ikm = bytearray()
    for part in [outer_prk, data_ikm, credential_prk]:
        ikm.extend(struct.pack('>I', len(part)))
        ikm.extend(part)
    
    return v3_hkdf_extract(salt, bytes(ikm))


def v3_handshake_prk(listener: dict, credential_prk: bytes,
                     outer_prk: bytes, data_ikm: bytes,
                     t_server_hello: bytes) -> bytes:
    """Derive handshake PRK for Finished messages."""
    salt = v3_hash('ewp/v3/handshake-salt', t_server_hello)
    
    ikm = bytearray()
    for part in [outer_prk, data_ikm, credential_prk]:
        ikm.extend(struct.pack('>I', len(part)))
        ikm.extend(part)
    
    return v3_hkdf_extract(salt, bytes(ikm))


def v3_finished_verify(key: bytes, label: str, transcript: bytes) -> bytes:
    """Compute Finished verify data using HMAC-SHA-256."""
    return hmac.new(
        key,
        v3_domain(label, transcript),
        hashlib.sha256
    ).digest()


def v3_master_prk(handshake_prk: bytes, t_server_finished: bytes) -> bytes:
    """Derive master PRK from handshake PRK."""
    salt = v3_hash('ewp/v3/master-salt', t_server_finished)
    return v3_hkdf_extract(salt, handshake_prk)


def v3_route_tag(credential: bytes, listener: dict, route_epoch: int) -> bytes:
    """Compute route tag from credential."""
    server_id = listener['server_id'].encode('utf-8')
    scope = listener['deployment_scope'].encode('utf-8')
    epoch_bytes = struct.pack('>Q', route_epoch)
    
    return hmac.new(
        credential,
        v3_domain('ewp/v3/route', server_id, scope, epoch_bytes),
        hashlib.sha256
    ).digest()[:16]


def v3_cookie(listener: dict, source: bytes, expires_at: int,
              prekey_id: bytes, bundle_digest: bytes, bundle_gen: int,
              init_nonce: bytes, client_nonce: bytes, core_digest: bytes,
              cookie_key: bytes) -> bytes:
    """Compute retry cookie."""
    version = struct.pack('>H', listener['version'])
    suite = struct.pack('>H', listener['suite'])
    server_id = listener['server_id'].encode('utf-8')
    scope = listener['deployment_scope'].encode('utf-8')
    
    input_data = v3_domain(
        'ewp/v3/cookie',
        version, suite, server_id, scope,
        source,
        struct.pack('>Q', expires_at),
        prekey_id, bundle_digest,
        struct.pack('>Q', bundle_gen),
        init_nonce, client_nonce, core_digest
    )
    
    return hmac.new(cookie_key, input_data, hashlib.sha256).digest()


def v3_admission_tag(credential: bytes, listener: dict,
                     init_bytes: bytes, retry_bytes: bytes,
                     core_bytes: bytes) -> bytes:
    """Compute admission tag."""
    credential_prk = v3_credential_prk(credential, listener)
    
    key = HKDFExpand(
        algorithm=hashes.SHA256(),
        length=32,
        info=b'ewp/v3/admission'
    ).derive(credential_prk)
    
    input_hash = v3_hash(
        'ewp/v3/admission-input',
        init_bytes, retry_bytes, core_bytes
    )
    
    return hmac.new(key, input_hash, hashlib.sha256).digest()


def v3_replay_key(key: bytes, listener: dict, principal: bytes,
                  prekey_id: bytes, init_nonce: bytes,
                  client_nonce: bytes, core_digest: bytes) -> bytes:
    """Compute replay key."""
    version = struct.pack('>H', listener['version'])
    suite = struct.pack('>H', listener['suite'])
    server_id = listener['server_id'].encode('utf-8')
    scope = listener['deployment_scope'].encode('utf-8')
    
    input_data = v3_domain(
        'ewp/v3/replay',
        version, suite, server_id, scope,
        principal, prekey_id, init_nonce, client_nonce, core_digest
    )
    
    return hmac.new(key, input_data, hashlib.sha256).digest()


def v3_encode_record(key: bytes, nonce_prefix: bytes, counter: int,
                     frame_type: int, meta: bytes, payload: bytes,
                     padding: bytes) -> bytes:
    """Encode one EWP/v3 opaque record.
    
    Format: RecordLen(4) || AEAD(Counter || Type || MetaLen || PayloadLen || Meta || Payload || Pad)
    """
    # Build plaintext
    plaintext = bytearray()
    plaintext.extend(struct.pack('>Q', counter))  # 8-byte counter
    plaintext.append(frame_type)                  # 1-byte type
    plaintext.extend(struct.pack('>H', len(meta)))  # 2-byte meta len
    plaintext.extend(struct.pack('>I', len(payload)))  # 4-byte payload len
    plaintext.extend(meta)
    plaintext.extend(payload)
    plaintext.extend(padding)
    
    # Construct nonce: prefix || counter
    nonce = bytearray(nonce_prefix)
    nonce.extend(struct.pack('>Q', counter))
    
    # AEAD seal
    aead = ChaCha20Poly1305(key)
    record_len_bytes = struct.pack('>I', len(plaintext) + 16)  # +16 for tag
    ciphertext = aead.encrypt(bytes(nonce), bytes(plaintext), record_len_bytes)
    
    return record_len_bytes + ciphertext


def verify_kat():
    """Verify all KAT vectors against independent oracle."""
    with open('v3_vectors.json', 'r') as f:
        vectors = json.load(f)
    
    listener = vectors['listener']
    credential = bytes.fromhex(vectors['credential_hex'])
    
    # Test 1: Credential PRK
    credential_prk = v3_credential_prk(credential, listener)
    expected = bytes.fromhex(vectors['expected']['credential_prk_hex'])
    assert credential_prk == expected, f"credential_prk mismatch"
    print("✓ credential_prk")
    
    # Test 2: Route tag
    route_tag = v3_route_tag(credential, listener, 7)
    expected = bytes.fromhex(vectors['expected']['route_tag_hex'])
    assert route_tag == expected, "route_tag mismatch"
    print("✓ route_tag")
    
    # Test 3: Outer PRK
    outer_ikm = bytes.fromhex(vectors['outer_ikm_hex'])
    t_init = bytes.fromhex(vectors['t_init_hex'])
    bundle_digest = bytes.fromhex(vectors['bundle_digest_hex'])
    client_header = vectors['client_hello_header'].encode('utf-8')
    
    outer_prk = v3_outer_prk(
        listener, credential_prk, outer_ikm,
        t_init, bundle_digest, client_header
    )
    expected = bytes.fromhex(vectors['expected']['outer_prk_hex'])
    assert outer_prk == expected, "outer_prk mismatch"
    print("✓ outer_prk")
    
    # Test 4: Server Hello PRK
    data_ikm = bytes.fromhex(vectors['data_ikm_hex'])
    t_client_hello = bytes.fromhex(vectors['t_client_hello_hex'])
    server_header = vectors['server_hello_header'].encode('utf-8')
    
    server_hello_prk = v3_server_hello_prk(
        listener, credential_prk, outer_prk, data_ikm,
        t_client_hello, server_header
    )
    expected = bytes.fromhex(vectors['expected']['server_hello_prk_hex'])
    assert server_hello_prk == expected, "server_hello_prk mismatch"
    print("✓ server_hello_prk")
    
    # Test 5: Handshake PRK
    t_server_hello = bytes.fromhex(vectors['t_server_hello_hex'])
    handshake_prk = v3_handshake_prk(
        listener, credential_prk, outer_prk, data_ikm, t_server_hello
    )
    expected = bytes.fromhex(vectors['expected']['handshake_prk_hex'])
    assert handshake_prk == expected, "handshake_prk mismatch"
    print("✓ handshake_prk")
    
    # Test 6: ClientHello key/nonce
    client_hello_key = v3_expand(
        outer_prk, 'client-hello/key', listener, t_init,
        'client', 'server', 'c2s', 0, 32
    )
    expected = bytes.fromhex(vectors['expected']['client_hello_key_hex'])
    assert client_hello_key == expected, "client_hello_key mismatch"
    print("✓ client_hello_key")
    
    client_hello_nonce = v3_expand(
        outer_prk, 'client-hello/nonce', listener, t_init,
        'client', 'server', 'c2s', 0, 12
    )
    expected = bytes.fromhex(vectors['expected']['client_hello_nonce_hex'])
    assert client_hello_nonce == expected, "client_hello_nonce mismatch"
    print("✓ client_hello_nonce")
    
    # Test 7: Finished verify keys
    client_finished_verify_key = v3_expand(
        handshake_prk, 'finished/client/verify', listener, t_server_hello,
        'client', 'server', 'c2s', 0, 32
    )
    expected = bytes.fromhex(vectors['expected']['client_finished_verify_key_hex'])
    assert client_finished_verify_key == expected, "client_finished_verify_key mismatch"
    print("✓ client_finished_verify_key")
    
    # Test 8: Master PRK
    t_server_finished = bytes.fromhex(vectors['expected']['server_finished_transcript_hex'])
    master_prk = v3_master_prk(handshake_prk, t_server_finished)
    expected = bytes.fromhex(vectors['expected']['master_prk_hex'])
    assert master_prk == expected, "master_prk mismatch"
    print("✓ master_prk")
    
    # Test 9: C2S/S2C keys
    c2s_key = v3_expand(
        master_prk, 'traffic/c2s/key', listener, t_server_finished,
        'client', 'server', 'c2s', 0, 32
    )
    expected = bytes.fromhex(vectors['expected']['c2s_key_hex'])
    assert c2s_key == expected, "c2s_key mismatch"
    print("✓ c2s_key")
    
    # Test 10: Cookie
    source = vectors['source'].encode('utf-8')
    cookie = v3_cookie(
        listener, source, vectors['expires_at'],
        bytes.fromhex(vectors['prekey_id_hex']),
        bundle_digest,
        vectors['bundle_generation'],
        bytes.fromhex(vectors['init_nonce_hex']),
        bytes.fromhex(vectors['client_nonce_hex']),
        bytes.fromhex(vectors['core_digest_hex']),
        bytes.fromhex(vectors['cookie_key_hex'])
    )
    expected = bytes.fromhex(vectors['expected']['cookie_hex'])
    assert cookie == expected, "cookie mismatch"
    print("✓ cookie")
    
    # Test 11: Admission tag
    admission_tag = v3_admission_tag(
        credential, listener,
        vectors['admission']['init'].encode('utf-8'),
        vectors['admission']['retry'].encode('utf-8'),
        vectors['admission']['core'].encode('utf-8')
    )
    expected = bytes.fromhex(vectors['expected']['admission_tag_hex'])
    assert admission_tag == expected, "admission_tag mismatch"
    print("✓ admission_tag")
    
    # Test 12: Replay key
    replay_key = v3_replay_key(
        bytes.fromhex(vectors['replay_key_material_hex']),
        listener,
        bytes.fromhex(vectors['principal_hex']),
        bytes.fromhex(vectors['prekey_id_hex']),
        bytes.fromhex(vectors['init_nonce_hex']),
        bytes.fromhex(vectors['client_nonce_hex']),
        bytes.fromhex(vectors['core_digest_hex'])
    )
    expected = bytes.fromhex(vectors['expected']['replay_key_hex'])
    assert replay_key == expected, "replay_key mismatch"
    print("✓ replay_key")
    
    # Test 13: Record encoding
    rec = vectors['record']
    wire = v3_encode_record(
        bytes.fromhex(rec['key_hex']),
        bytes.fromhex(rec['nonce_prefix_hex']),
        0,  # counter
        rec['type'],
        bytes.fromhex(rec['meta_hex']),
        bytes.fromhex(rec['payload_hex']),
        bytes.fromhex(rec['padding_hex'])
    )
    expected = bytes.fromhex(rec['wire_hex'])
    assert wire == expected, "record wire encoding mismatch"
    print("✓ record encoding")
    
    print("\n✅ All KAT vectors verified by independent Python oracle")


if __name__ == '__main__':
    verify_kat()
