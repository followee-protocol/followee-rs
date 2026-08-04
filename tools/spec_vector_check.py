#!/usr/bin/env python3
"""Independent re-derivation of the Followee specification Appendix B vectors.

PROVENANCE WARNING: this script was authored on 2026-08-04 with the full
specification, whitepaper, and implementation brief in context. It is a
spec-review aid and fixture sanity check ONLY. It is NOT the Milestone 1.5
clean-room Python model (IMPLEMENTATION.md section 11.4) and MUST NOT be shown
to, reused by, or placed in the authoring context of that model's separate
session. It also uses pyca/cryptography's ordinary Ed25519 verify, which is
NOT a Followee-strict section 3.3 verifier.

Verified against spec v0.2 vectors: 27/27 values reproduce byte-for-byte.
Requires: python3 with the `cryptography` package.
"""
import hashlib
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives import serialization

H = bytes.fromhex
ok_count = fail_count = 0

def check(name, got, expected):
    global ok_count, fail_count
    if got == expected:
        ok_count += 1
        print(f"  OK   {name}")
    else:
        fail_count += 1
        print(f"  FAIL {name}\n       got      {got if isinstance(got,str) else got.hex()}\n       expected {expected if isinstance(expected,str) else expected.hex()}")

# ---------- minimal deterministic CBOR encoder (definite lengths, minimal ints) ----------
def enc_head(major, val):
    if val < 24: return bytes([(major << 5) | val])
    if val < 0x100: return bytes([(major << 5) | 24, val])
    if val < 0x10000: return bytes([(major << 5) | 25]) + val.to_bytes(2, 'big')
    if val < 0x100000000: return bytes([(major << 5) | 26]) + val.to_bytes(4, 'big')
    return bytes([(major << 5) | 27]) + val.to_bytes(8, 'big')

def enc(v):
    if isinstance(v, bool): raise ValueError
    if isinstance(v, int):
        return enc_head(0, v) if v >= 0 else enc_head(1, -1 - v)
    if isinstance(v, bytes): return enc_head(2, len(v)) + v
    if isinstance(v, str):
        b = v.encode(); return enc_head(3, len(b)) + b
    if isinstance(v, list): return enc_head(4, len(v)) + b''.join(enc(x) for x in v)
    if isinstance(v, dict):
        items = sorted((enc(k), enc(val)) for k, val in v.items())
        return enc_head(5, len(items)) + b''.join(k + val for k, val in items)
    raise ValueError(type(v))

# ---------- base58btc ----------
B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
def b58encode(b):
    n = int.from_bytes(b, 'big'); s = ''
    while n: n, r = divmod(n, 58); s = B58[r] + s
    return '1' * (len(b) - len(b.lstrip(b'\x00'))) + s

def pub_from_seed(seed_hex):
    sk = Ed25519PrivateKey.from_private_bytes(H(seed_hex))
    return sk.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw), sk

def sign(sk, msg): return sk.sign(msg)
def verify(pub, sig, msg):
    try:
        Ed25519PublicKey.from_public_bytes(pub).verify(sig, msg); return True
    except Exception:
        return False

def pk_cbor(pub): return enc({0: -19, 1: pub})
def rev_commitment(pub): return hashlib.sha256(b"Followee/RevocationKey/v1\x00" + pk_cbor(pub)).digest()
def descriptor_cbor(root_pub, commitment): return enc({0: 1, 1: {0: -19, 1: root_pub}, 2: commitment})
def did_from_descriptor(desc_bytes):
    digest = hashlib.sha256(b"Followee/AuthorityDescriptor/v1\x00" + desc_bytes).digest()
    return digest, "did:flw:z" + b58encode(b'\x12\x20' + digest)

def sig_structure(body): return enc(["Signature1", H("a10132"), b"Followee/IdentityRecord/v1", body])
def envelope(body, sig):
    # tag 18 array [protected, unprotected {}, payload, signature]; minimal tag head = 0xd2
    return enc_head(6, 18) + enc_head(4,4) + enc(H("a10132")) + b'\xa0' + enc(body) + enc(sig)

print("=== B.2 keys ===")
root_pub, root_sk = pub_from_seed("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
check("root public key", root_pub, H("03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8"))
rev_pub, rev_sk = pub_from_seed("202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f")
check("revocation public key", rev_pub, H("29acbae141bccaf0b22e1a94d34d0bc7361e526d0bfe12c89794bc9322966dd7"))

print("=== B.3 commitment / descriptor / DID ===")
check("revocation public-key CBOR", pk_cbor(rev_pub),
      H("a2003201582029acbae141bccaf0b22e1a94d34d0bc7361e526d0bfe12c89794bc9322966dd7"))
rc = rev_commitment(rev_pub)
check("revocation commitment", rc, H("d123bafb7ae35472d9a73944d98314a38ff8f201d79c32e640f97a27bec880de"))
desc = descriptor_cbor(root_pub, rc)
check("Authority Descriptor CBOR", desc, H("a3000101a2003201582003a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8025820d123bafb7ae35472d9a73944d98314a38ff8f201d79c32e640f97a27bec880de"))
digest, did = did_from_descriptor(desc)
check("descriptor digest", digest, H("12dc4b843d10c5ca7313aa2452db61d661afbe3943b3fdbea43405c7028d1eb2"))
check("Followee DID", did, "did:flw:zQmPcGstBa7wW9hoYQbS6JZ4UxwZmoKr7YVf9y7qxiyD3Cm")

print("=== B.4 root record ===")
contact = {0: "Alice Example", 1: "Writer", 3: ["acct:alice@example.com"],
           4: [{0: "feed", 1: "Feed", 2: "https://alice.example/feed.xml",
                3: "application/atom+xml", 4: "Writing"}]}
body4 = enc({0: 1, 1: did, 2: 1785589200123, 3: 0,
             4: {0: 1, 1: {0: -19, 1: root_pub}, 2: rc}, 7: contact})
check("record body CBOR", body4, H("a600010178376469643a666c773a7a516d5063477374426137775739686f59516253364a5a345578775a6d6f4b7237595666397937717869794433436d021b0000019fbd68f4fb030004a3000101a2003201582003a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8025820d123bafb7ae35472d9a73944d98314a38ff8f201d79c32e640f97a27bec880de07a4006d416c696365204578616d706c650166577269746572038176616363743a616c696365406578616d706c652e636f6d0481a500646665656401644665656402781e68747470733a2f2f616c6963652e6578616d706c652f666565642e786d6c03746170706c69636174696f6e2f61746f6d2b786d6c046757726974696e67"))
ss4 = sig_structure(body4)
check("Sig_structure length == 327", str(len(ss4)), "327")
check("Sig_structure bytes", ss4, H("846a5369676e61747572653143a10132581a466f6c6c6f7765652f4964656e746974795265636f72642f7631590118a600010178376469643a666c773a7a516d5063477374426137775739686f59516253364a5a345578775a6d6f4b7237595666397937717869794433436d021b0000019fbd68f4fb030004a3000101a2003201582003a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8025820d123bafb7ae35472d9a73944d98314a38ff8f201d79c32e640f97a27bec880de07a4006d416c696365204578616d706c650166577269746572038176616363743a616c696365406578616d706c652e636f6d0481a500646665656401644665656402781e68747470733a2f2f616c6963652e6578616d706c652f666565642e786d6c03746170706c69636174696f6e2f61746f6d2b786d6c046757726974696e67"))
check("body digest", hashlib.sha256(body4).digest(), H("f8e387942fd568c72d629717f579314a3305f26e03b7197958c7555b2e9573c7"))
sig4 = sign(root_sk, ss4)
check("signature (deterministic Ed25519)", sig4, H("4db146d7bc6ca7690bac44b0c6ef38bcdd685ff157fdcca15da6b64662a26f94bd95b88f97f3e720246b3756c6eb6b8967103f9346dbef51c053cac381a50204"))
check("complete envelope", envelope(body4, sig4), H("d28443a10132a0590118a600010178376469643a666c773a7a516d5063477374426137775739686f59516253364a5a345578775a6d6f4b7237595666397937717869794433436d021b0000019fbd68f4fb030004a3000101a2003201582003a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8025820d123bafb7ae35472d9a73944d98314a38ff8f201d79c32e640f97a27bec880de07a4006d416c696365204578616d706c650166577269746572038176616363743a616c696365406578616d706c652e636f6d0481a500646665656401644665656402781e68747470733a2f2f616c6963652e6578616d706c652f666565642e786d6c03746170706c69636174696f6e2f61746f6d2b786d6c046757726974696e6758404db146d7bc6ca7690bac44b0c6ef38bcdd685ff157fdcca15da6b64662a26f94bd95b88f97f3e720246b3756c6eb6b8967103f9346dbef51c053cac381a50204"))

print("=== B.5 root-revoked record ===")
body5 = enc({0: 1, 1: did, 2: 1785589201123, 3: 1,
             4: {0: 1, 1: {0: -19, 1: root_pub}, 2: rc},
             5: {0: -19, 1: rev_pub}, 7: contact})
check("record body CBOR", body5, H("a700010178376469643a666c773a7a516d5063477374426137775739686f59516253364a5a345578775a6d6f4b7237595666397937717869794433436d021b0000019fbd68f8e3030104a3000101a2003201582003a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8025820d123bafb7ae35472d9a73944d98314a38ff8f201d79c32e640f97a27bec880de05a2003201582029acbae141bccaf0b22e1a94d34d0bc7361e526d0bfe12c89794bc9322966dd707a4006d416c696365204578616d706c650166577269746572038176616363743a616c696365406578616d706c652e636f6d0481a500646665656401644665656402781e68747470733a2f2f616c6963652e6578616d706c652f666565642e786d6c03746170706c69636174696f6e2f61746f6d2b786d6c046757726974696e67"))
check("body digest", hashlib.sha256(body5).digest(), H("3c617919801d0c19684144f9b46e0f2384243c17c831a2d76531ba6554cb3861"))
sig5 = sign(rev_sk, sig_structure(body5))
check("signature (revocation key)", sig5, H("c874ee1bb01dc4f3972b978455abba78ab0f84755fbd9ee01425a1e6c910abae7cfa8b407aff2092be09e9032e968a23a87e63f9e1e7b2a0d5498bf7df5d6c09"))

print("=== B.6 equal-time ordering ===")
for name, exp in (("Alice A", "6f347840328b2b2cd74cce2f9a222a313e9d9504305c3ac816987ff2f4b47d97"),
                  ("Alice B", "8123f2cdf1a414b34d38eb2e58b39fb7cf37e9f851d999402f64787b3361c162")):
    c2 = dict(contact); c2[0] = name
    b = enc({0: 1, 1: did, 2: 1785589200123, 3: 0,
             4: {0: 1, 1: {0: -19, 1: root_pub}, 2: rc}, 7: c2})
    check(f'"{name}" body digest', hashlib.sha256(b).digest(), H(exp))

print("=== B.8 descriptor substitution ===")
atk_root_pub, atk_root_sk = pub_from_seed("404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f")
check("attacker root public key", atk_root_pub, H("2543b92ff1095511476adc8369db6ddc933665a11978dda1404ee1066ca9559d"))
atk_rev_pub, _ = pub_from_seed("606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f")
check("attacker revocation public key", atk_rev_pub, H("174553b456dddfc6908ecab1c101fe6ab21e2baa0617795b7d43a63482993fd5"))
atk_rc = rev_commitment(atk_rev_pub)
check("attacker revocation commitment", atk_rc, H("2a35f76c8bcc0c5fc69e99d51656c2a93a1c8e447677d6f78c8c9d729eef3ca6"))
atk_desc = descriptor_cbor(atk_root_pub, atk_rc)
check("attacker Authority Descriptor CBOR", atk_desc, H("a3000101a200320158202543b92ff1095511476adc8369db6ddc933665a11978dda1404ee1066ca9559d0258202a35f76c8bcc0c5fc69e99d51656c2a93a1c8e447677d6f78c8c9d729eef3ca6"))
_, atk_did = did_from_descriptor(atk_desc)
check("attacker's own DID", atk_did, "did:flw:zQmPdjR6k8HFgbf4e51P7iMy4aY3buGsxQU49fSHdGhce7s")
body8 = enc({0: 1, 1: did, 2: 1785589200123, 3: 0,
             4: {0: 1, 1: {0: -19, 1: atk_root_pub}, 2: atk_rc}, 7: contact})
check("substituted body digest", hashlib.sha256(body8).digest(), H("1ca53f60b31bec6334d0c0449cd639d5c8b2922549287ba00cf40df018164e68"))
sig8 = sign(atk_root_sk, sig_structure(body8))
check("attacker signature", sig8, H("b8352e21b1168a4c74020f2b7cf10b519fda4fb0c2465a682328f802c08b1873e1b1c137b79cce7f81aa00fc1a5630e34c19500a016b45867c9900108625650e"))
# sanity: the substituted record's descriptor must NOT reproduce Alice's DID
_, sub_did = did_from_descriptor(atk_desc)
check("descriptor binding correctly fails (attacker desc != Alice DID)", str(sub_did != did), "True")

print("=== IMPLEMENTATION.md item 14: S + L mutated signature ===")
L = 2**252 + 27742317777372353535851937790883648493
S = int.from_bytes(sig4[32:], 'little')
mutated = sig4[:32] + ((S + L).to_bytes(32, 'little'))
check("S+L 64-byte signature", mutated, H("4db146d7bc6ca7690bac44b0c6ef38bcdd685ff157fdcca15da6b64662a26f94aa69aeecb156fa78fa072ff9a4e54a9e67103f9346dbef51c053cac381a50214"))
strict_rejects = not verify(root_pub, mutated, ss4)
print(f"  note: cryptography lib rejects S+L signature: {strict_rejects}")

print(f"\n{ok_count} OK, {fail_count} FAIL")
