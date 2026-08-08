#!/usr/bin/env python3
"""Independent re-derivation of the Followee specification Appendix B vectors.

PROVENANCE WARNING: this script was authored on 2026-08-04 with the full
specification, whitepaper, and implementation brief in context. It is a
spec-review aid and fixture sanity check ONLY. It is NOT the Milestone 1.5
clean-room Python model (IMPLEMENTATION.md section 11.4) and MUST NOT be shown
to, reused by, or placed in the authoring context of that model's separate
session. It also uses pyca/cryptography's ordinary Ed25519 verify, which is
NOT a Followee-strict section 3.3 verifier.

Verified against spec v0.8.1 vectors (Appendix B.2–B.12): 82/82 values
reproduce byte-for-byte, including the B.9 Bob identity, the B.10
fault-isolated basic-validity signatures, the B.11 wrapper lengths and
SHA-256 digests, and the B.12 schema-disallowed simple-value signatures.
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

print("=== B.9 Bob identity (v0.8) ===")
bob_pub, bob_sk = pub_from_seed("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f")
check("Bob root public key", bob_pub, H("cd14b37f956e953194ff7fb73b3d81dcc561d61a7538094b7c3e1a643ee5f3aa"))
bob_rev_pub, _ = pub_from_seed("a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf")
check("Bob revocation public key", bob_rev_pub, H("4fd099ccd47d7893dfe9ec24414ecb0d9b5420232aad30d91c465be33cbe65c4"))
check("Bob revocation public-key CBOR", pk_cbor(bob_rev_pub),
      H("a200320158204fd099ccd47d7893dfe9ec24414ecb0d9b5420232aad30d91c465be33cbe65c4"))
bob_rc = rev_commitment(bob_rev_pub)
check("Bob revocation commitment", bob_rc, H("46ed171c07da81226f954a36b2e61c3be4caee1f7b5d78aa6022eedb69486c41"))
bob_desc = descriptor_cbor(bob_pub, bob_rc)
check("Bob Authority Descriptor CBOR", bob_desc, H("a3000101a20032015820cd14b37f956e953194ff7fb73b3d81dcc561d61a7538094b7c3e1a643ee5f3aa02582046ed171c07da81226f954a36b2e61c3be4caee1f7b5d78aa6022eedb69486c41"))
bob_digest, bob_did = did_from_descriptor(bob_desc)
check("Bob descriptor digest", bob_digest, H("ddc23bec60a7a9dad831d8c52439b9f3f30e17012da4d948233ece41154817ba"))
check("Bob Followee DID", bob_did, "did:flw:zQmdGJbJu6pBbiyZX9gJHBTFxnUCtBgRa7mZRcKKs1TcFEy")
bob_contact = {0: "Bob Example", 1: "Reader", 3: ["acct:bob@example.net"],
               4: [{0: "feed", 1: "Feed", 2: "https://bob.example/feed.xml",
                    3: "application/atom+xml", 4: "Reading"}]}
body9 = enc({0: 1, 1: bob_did, 2: 1785589201123, 3: 0,
             4: {0: 1, 1: {0: -19, 1: bob_pub}, 2: bob_rc}, 7: bob_contact})
check("Bob record body CBOR", body9, H("a600010178376469643a666c773a7a516d64474a624a753670426269795a5839674a48425446786e55437442675261376d5a52634b4b73315463464579021b0000019fbd68f8e3030004a3000101a20032015820cd14b37f956e953194ff7fb73b3d81dcc561d61a7538094b7c3e1a643ee5f3aa02582046ed171c07da81226f954a36b2e61c3be4caee1f7b5d78aa6022eedb69486c4107a4006b426f62204578616d706c650166526561646572038174616363743a626f62406578616d706c652e6e65740481a500646665656401644665656402781c68747470733a2f2f626f622e6578616d706c652f666565642e786d6c03746170706c69636174696f6e2f61746f6d2b786d6c046752656164696e67"))
ss9 = sig_structure(body9)
check("Bob Sig_structure length == 321", str(len(ss9)), "321")
check("Bob body digest", hashlib.sha256(body9).digest(), H("c7d107d8004c0376b453d7de0eaf187f0597e0b4edccac307a81ddba3b8fcda8"))
sig9 = sign(bob_sk, ss9)
check("Bob signature", sig9, H("958a63029defee36e1047c002a8346aa57c832ed8fc27781ee622cc92330bc434c8f075aa89290b2c1021bf19602a92b5681ae6615268ed928bd113f15c60202"))
env9 = envelope(body9, sig9)
check("Bob complete envelope tail", env9[-64:], sig9)

print("=== B.10 fault-isolated basic-validity records (v0.8) ===")
EXT_KEY = "https://example.com/ext"
b10_values = [
    ("duplicate-key", enc_head(5, 2) + enc(0) + enc(0) + enc(0) + enc(1),
     "128fec939e1273f890be281a82f7bfac1134e3bab9bc0651022f3a6000698dd2", 358,
     "afba8e1577abd9c6383b8df9a5c05913df217b3f1c4dc0c4c0027f9a44629d1a397dd4ad36f6e01028a3060a8481690cc589e2f9525e597f0a6a0cf60c9cb404"),
    ("overlong U+002E", enc_head(3, 2) + b"\xc0\xae",
     "4b8cc526c781c6b9ba707b6393f392f1132b0e5d18a7e7611a583d1013278f70", 356,
     "738365f103b6f943311c4f339bcd4889e405129e2643d57f2fd3698adc50d8da8df529b886252b62727233a828769dabcac7c0add28f442e72c325905844a50e"),
    ("lone U+D800", enc_head(3, 3) + b"\xed\xa0\x80",
     "fd9cbe63338d1a3a1791c596db9a3824376070a7126aab2064d90bd62333afe8", 357,
     "7fcefa0e654da023a71dc8ed5e2cb988ac4111a9b3a75e88c5757e2b59d792e965ff004eae3c26c13e29fe56c7addec04fad04e4f18e5ba375a827c02028e103"),
    ("U+110000", enc_head(3, 4) + b"\xf4\x90\x80\x80",
     "95bfb5eb8a921a0b7ceeff63a81ccd6404cf7e64945d9d888805f208b49e4204", 358,
     "28ecb7c9e471940d077cd3d24f1e348aaac855be352523ae9867ef2839bbdf6d8794f110e0d4a79055009dd803afdd259729c16c70746acab0ad620d190e0607"),
    ("incomplete 3-byte", enc_head(3, 2) + b"\xe2\x82",
     "60e93b06213c6038ab697b796f8264cc854dc12442efbf15f2abd35eae165e09", 356,
     "e7cd9850280f108e8caf550cdff381765c957dc53993b28a57d8f4b362f5e624105d83ffe12b22df2d3ca8d54c833030f1fa1617cd1e4b8697f670aa41d7c601"),
]
for name, value_bytes, digest_hex, ss_len, sig_hex in b10_values:
    raw = bytearray(body4)
    assert raw[0] == 0xA6
    raw[0] = 0xA7
    raw += enc(8) + enc_head(5, 1) + enc(EXT_KEY) + value_bytes
    raw = bytes(raw)
    check(f"B.10 {name} body digest", hashlib.sha256(raw).digest(), H(digest_hex))
    ss10 = sig_structure(raw)
    check(f"B.10 {name} Sig_structure length == {ss_len}", str(len(ss10)), str(ss_len))
    check(f"B.10 {name} signature (Alice root key)", sign(root_sk, ss10), H(sig_hex))

print("=== B.11 relay-wrapper vectors (v0.8) ===")
GEN = H("000102030405060708090a0b0c0d0e0f")
env4 = envelope(body4, sig4)
body8_env = H("d28443a10132a0590118a600010178376469643a666c773a7a516d5063477374426137775739686f59516253364a5a345578775a6d6f4b7237595666397937717869794433436d021b0000019fbd68f4fb030004a3000101a200320158202543b92ff1095511476adc8369db6ddc933665a11978dda1404ee1066ca9559d0258202a35f76c8bcc0c5fc69e99d51656c2a93a1c8e447677d6f78c8c9d729eef3ca607a4006d416c696365204578616d706c650166577269746572038176616363743a616c696365406578616d706c652e636f6d0481a500646665656401644665656402781e68747470733a2f2f616c6963652e6578616d706c652f666565642e786d6c03746170706c69636174696f6e2f61746f6d2b786d6c046757726974696e675840b8352e21b1168a4c74020f2b7cf10b519fda4fb0c2465a682328f802c08b1873e1b1c137b79cce7f81aa00fc1a5630e34c19500a016b45867c9900108625650e")

def check_wrapper(name, built, length, sha_hex, exact_hex=None):
    check(f"{name} length == {length}", str(len(built)), str(length))
    check(f"{name} SHA-256", hashlib.sha256(built).digest(), H(sha_hex))
    if exact_hex:
        check(f"{name} exact bytes", built, H(exact_hex))

# B.11.1: duplicate top-level label 1 entries — manual, enc() cannot emit it.
b11_1 = enc_head(5, 3) + enc(0) + enc(1) + enc(1) + enc([did]) + enc(1) + enc([bob_did])
check_wrapper("B.11.1 request", b11_1, 121, "0f3aa1e98de0c1d63a2dd740e04542be326e550e75a133ade1ac045694bfb790")

# B.11.2: protocol version non-minimally encoded as 18 01.
b11_2 = enc_head(5, 3) + enc(0) + b"\x18\x01" + enc(1) + enc(GEN) + enc(2) + enc([{0: 2}])
check_wrapper("B.11.2 response", b11_2, 27, "251497e0a44248c6099c5851e0c6668c0731d2b7f1f610f28c6f3c42254475cf")

check_wrapper("B.11.3 request", enc({0: 1, 1: [did, bob_did]}), 119,
              "a2d1d1944182db0f42468bdcaeb086d1987ee3570b892811a378f0ec3bbbca78")
check_wrapper("B.11.3 response",
              enc({0: 1, 1: GEN, 2: [{0: 0, 1: body8_env}, {0: 0, 1: env9}]}), 743,
              "62246877adbd56be2996ea37d05475d88c0e7932ff9b042f8ddbb9a809f8f4ca")

check_wrapper("B.11.4 request", enc({0: 1, 1: [did, did, bob_did]}), 176,
              "ea2c9422529945ce78406f486c80ad633a1e90726cd493dedfa4347df373cf73")
check_wrapper("B.11.4 response",
              enc({0: 1, 1: GEN, 2: [{0: 0, 1: env4}, {0: 0, 1: env4}, {0: 0, 1: env9}]}), 1106,
              "203e22e2d913359b08070c289d60889770bcdeee0584187dee25e1c8e05fdfe8")

check_wrapper("B.11.5 request", enc({0: 1, 1: b"v08-0000", 2: 2, 3: 1048576}), 21,
              "e65ad99bab6cd0eefba501a8e65ecfb30ad8ad453da9e554346e2becaab339df")
# enc() deliberately refuses booleans, so the changes-response wrappers with
# `hasMore = false` (f4) are assembled manually in deterministic label order.
b11_5_resp = enc_head(5, 6) + enc(0) + enc(1) + enc(1) + enc(0) + enc(2) + \
    enc([[did, {0: 0, 1: body8_env}, 1001], [bob_did, {0: 0, 1: env9}, 1002]]) + \
    enc(3) + enc(b"v08-0002") + enc(4) + b"\xf4" + enc(5) + enc(GEN)
check_wrapper("B.11.5 response", b11_5_resp, 879,
              "3337aa0be1d6b8cbf856a31657490398a4b778de586e0b292da68c5c26c200f2")

check_wrapper("B.11.6 request", enc({0: 1, 1: [did, "did:flw:not-a-multibase", bob_did]}), 143,
              "8276648c9938dcc57a004695414bc7bd6776186b8df1626210667abf1c9ccf38")
check_wrapper("B.11.6 response",
              enc({0: 1, 1: GEN, 2: [{0: 0, 1: env4}, {0: 3, 2: 0}, {0: 0, 1: env9}]}), 748,
              "d8a36364ed62a8fabb905f6c20c04304fe1803df10fa1680840c5c7cd1af96fa")

atk_env7 = enc_head(5, 6) + enc(0) + enc(1) + enc(1) + enc(0) + enc(2) + \
    enc([[did, {0: 0, 1: body8_env}, 1001], [bob_did, {0: 0, 1: env9}, 1002],
         [atk_did, {0: 1, 1: 0}, 1003]]) + \
    enc(3) + enc(b"v08-0003") + enc(4) + b"\xf4" + enc(5) + enc(GEN)
check_wrapper("B.11.7 response", atk_env7, 945,
              "334740ea2ce15b4b70dfcdd88f4cfc7f31bfd53f1b7615aa08df1c4137f4d795")

print("=== B.12 fault-isolated schema-disallowed-simple-value records (v0.8.1) ===")
# Same construction as B.10 (B.4 body head a6 -> a7, label 8, extension map
# keyed by https://example.com/ext), with a deterministically encoded simple
# value the v1 extension-value schema does not admit. f0 is the shortest
# one-byte encoding of simple 16; f8 20 the shortest two-byte encoding of
# simple 32. Expected classification: schemaViolation (not covered here —
# this script derives bytes, digests, and signatures only).
b12_values = [
    ("simple value 16", b"\xf0",
     "0f08c916dbe92d5bebe06804f4e3bf5a1e23c7f32360638cd7d10a9b15cca1cf", 354,
     "6984d30e32b516e59450cd22c14b7bb6c93b83dad2ce9850e70691a4b76363bfd9823f60151c1c77dfe41f476e4183e28f4e676bbff536d558b96abc2c8e8c0d"),
    ("simple value 32", b"\xf8\x20",
     "2687c33152622b00dad17f6389a6d781d6065fe3a19e5bf98575d15440e3ff49", 355,
     "1a30f8094723a03835429225a43c500c6cf7b68bbee3fb4e98145215fef849e680e091bae1fec9f07288c7d4ef9c1f235a5272f25260a0e49425036215a4cc06"),
]
for name, value_bytes, digest_hex, ss_len, sig_hex in b12_values:
    raw = bytearray(body4)
    assert raw[0] == 0xA6
    raw[0] = 0xA7
    raw += enc(8) + enc_head(5, 1) + enc(EXT_KEY) + value_bytes
    raw = bytes(raw)
    check(f"B.12 {name} body digest", hashlib.sha256(raw).digest(), H(digest_hex))
    ss12 = sig_structure(raw)
    check(f"B.12 {name} Sig_structure length == {ss_len}", str(len(ss12)), str(ss_len))
    check(f"B.12 {name} signature (Alice root key)", sign(root_sk, ss12), H(sig_hex))

print(f"\n{ok_count} OK, {fail_count} FAIL")
