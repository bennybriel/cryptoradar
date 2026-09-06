"""
detectors.py — Cryptographic primitive detection signatures.

Each Signature is a language-agnostic-ish regex pattern mapped to:
  - the crypto primitive it flags
  - why it matters for quantum-readiness / general crypto-agility
  - a migration hint

Signatures are intentionally regex-based (not full AST parsing) so the
scanner works across the mixed-language reality of African fintech stacks:
COBOL/Java mainframe cores, Java/Spring middleware, Node/Python/PHP API
layers, and mobile clients — without needing a compiler toolchain for each.
"""

from __future__ import annotations
import re
from dataclasses import dataclass, field
from enum import Enum


class Category(str, Enum):
    ASYMMETRIC_QUANTUM_BREAKABLE = "asymmetric_quantum_breakable"   # Shor's algorithm kills these
    SYMMETRIC_QUANTUM_WEAKENED = "symmetric_quantum_weakened"       # Grover halves effective strength
    HASH_WEAK = "hash_weak"                                          # broken/weak classically already
    CIPHER_WEAK = "cipher_weak"                                      # broken/deprecated classically
    PROTOCOL_WEAK = "protocol_weak"                                  # TLS/SSL version issues
    KEY_MGMT = "key_management"                                      # hardcoded keys, weak RNG, static IV
    HARDCODED_SECRET = "hardcoded_secret"
    PQC_PRESENT = "pqc_present"                                      # good news signal


@dataclass
class Signature:
    id: str
    pattern: str
    category: Category
    primitive: str
    severity: int  # 1 (info) - 5 (critical)
    quantum_relevant: bool
    note: str
    migration_hint: str
    languages: tuple = ("*",)
    flags: int = re.IGNORECASE
    _compiled: re.Pattern = field(init=False, repr=False, compare=False)

    def __post_init__(self):
        self._compiled = re.compile(self.pattern, self.flags)

    def finditer(self, text: str):
        return self._compiled.finditer(text)


# ---------------------------------------------------------------------------
# Signature catalogue
# ---------------------------------------------------------------------------
# Severity scale (independent of quantum-relevance):
#   5 = broken/critical today (MD5 signing, DES, RC4, hardcoded secrets)
#   4 = strong today but quantum-breakable at scale (RSA, ECDSA, ECDH, DH)
#   3 = weak parameters (short RSA/EC keys, TLS 1.0/1.1, SHA-1 in non-collision-critical use)
#   2 = quantum-weakened but classically fine short-term (AES-128, SHA-256 sig-only contexts)
#   1 = informational / good signal (PQC already present)

SIGNATURES: list[Signature] = [

    # --- Asymmetric, quantum-breakable via Shor's algorithm ---------------
    Signature(
        id="RSA-KEYGEN",
        pattern=r"\bRSA\b(?!.*ML-KEM)",
        category=Category.ASYMMETRIC_QUANTUM_BREAKABLE,
        primitive="RSA",
        severity=4,
        quantum_relevant=True,
        note="RSA key exchange/signatures are broken by a cryptographically "
             "relevant quantum computer (Shor's algorithm). Common in JWT "
             "signing (RS256/RS384/RS512), TLS certs, and mainframe field-level encryption.",
        migration_hint="Plan migration to ML-DSA (signatures) / ML-KEM (key "
                        "establishment), or a hybrid RSA+PQC mode during transition.",
    ),
    Signature(
        id="ECDSA-ECDH",
        pattern=r"\b(ECDSA|ECDH|EllipticCurve|secp256|secp384|prime256v1|P-256|P-384)\b",
        category=Category.ASYMMETRIC_QUANTUM_BREAKABLE,
        primitive="ECDSA/ECDH",
        severity=4,
        quantum_relevant=True,
        note="Elliptic-curve schemes (ES256 JWTs, TLS ECDHE, mobile-app "
             "signing) are also broken by Shor's algorithm, and typically "
             "with a smaller quantum computer than RSA requires.",
        migration_hint="Migrate signatures to ML-DSA/SLH-DSA and key "
                        "exchange to ML-KEM; consider hybrid X25519+ML-KEM "
                        "for TLS during the transition window.",
    ),
    Signature(
        id="DIFFIE-HELLMAN",
        pattern=r"\b(DiffieHellman|DHParameterSpec|\bDH\b)\b",
        category=Category.ASYMMETRIC_QUANTUM_BREAKABLE,
        primitive="Diffie-Hellman",
        severity=4,
        quantum_relevant=True,
        note="Classic (non-EC) Diffie-Hellman key exchange is broken by Shor's algorithm.",
        migration_hint="Replace with ML-KEM (FIPS 203) for key establishment.",
    ),
    Signature(
        id="JWT-RS-ES-ALG",
        pattern=r'["\']?(RS256|RS384|RS512|ES256|ES384|ES512|PS256|PS384|PS512)["\']?',
        category=Category.ASYMMETRIC_QUANTUM_BREAKABLE,
        primitive="JWT asymmetric alg (RSA/EC family)",
        severity=4,
        quantum_relevant=True,
        note="JWT signing algorithm relies on RSA or EC math — quantum-breakable.",
        migration_hint="No standardized PQC JWT `alg` yet; track IETF COSE/JOSE "
                        "PQC drafts and design your JWKS rotation so the `kid` "
                        "and `alg` fields can be swapped without a breaking release.",
    ),

    # --- Symmetric, quantum-weakened (Grover) ------------------------------
    Signature(
        id="AES-128",
        pattern=r"\bAES[/_-]?128\b|AES\.getInstance\(.*128",
        category=Category.SYMMETRIC_QUANTUM_WEAKENED,
        primitive="AES-128",
        severity=2,
        quantum_relevant=True,
        note="Grover's algorithm roughly halves effective symmetric key "
             "strength, so AES-128 gives ~64-bit post-quantum security margin.",
        migration_hint="Prefer AES-256 (or ChaCha20-Poly1305 with a 256-bit "
                        "key) for anything with a multi-year confidentiality horizon.",
    ),

    # --- Broken/weak hashes -------------------------------------------------
    Signature(
        id="MD5",
        pattern=r"\bMD5\b",
        category=Category.HASH_WEAK,
        primitive="MD5",
        severity=5,
        quantum_relevant=False,
        note="MD5 is cryptographically broken (collision attacks are cheap "
             "today) and quantum computing is not even the relevant threat model here.",
        migration_hint="Use SHA-256/SHA-3 for integrity; use a proper "
                        "password hash (Argon2id/bcrypt/scrypt) for credentials.",
    ),
    Signature(
        id="SHA1",
        pattern=r"\bSHA-?1\b",
        category=Category.HASH_WEAK,
        primitive="SHA-1",
        severity=4,
        quantum_relevant=False,
        note="SHA-1 has practical collision attacks (SHAttered, 2017) and "
             "should not be used for signatures or integrity of new data.",
        migration_hint="Migrate to SHA-256/384/512 or SHA-3.",
    ),

    # --- Broken/weak ciphers --------------------------------------------
    Signature(
        id="DES-3DES",
        pattern=r"\b(DESede|TripleDES|3DES|\bDES\b)(?!ede.*key)",
        category=Category.CIPHER_WEAK,
        primitive="DES/3DES",
        severity=5,
        quantum_relevant=False,
        note="DES (56-bit) and 3DES are broken/deprecated. Frequently found "
             "wedged into legacy core-banking field encryption and old POS/ISO-8583 stacks.",
        migration_hint="Replace with AES-256-GCM. Note: this often requires "
                        "a coordinated re-encryption of data-at-rest, not just a code change.",
    ),
    Signature(
        id="RC4",
        pattern=r"\bRC4\b",
        category=Category.CIPHER_WEAK,
        primitive="RC4",
        severity=5,
        quantum_relevant=False,
        note="RC4 is a broken stream cipher; still occasionally found in legacy TLS configs or bespoke session tokens.",
        migration_hint="Replace with AES-256-GCM or ChaCha20-Poly1305.",
    ),
    Signature(
        id="ECB-MODE",
        pattern=r"AES/ECB|Cipher\.getInstance\(\s*[\"']AES[\"']\s*\)|createCipher\(\s*['\"]aes-128-ecb",
        category=Category.CIPHER_WEAK,
        primitive="AES-ECB mode",
        severity=4,
        quantum_relevant=False,
        note="ECB mode leaks data patterns (the classic 'ECB penguin' problem) — "
             "a design flaw independent of key size.",
        migration_hint="Use an authenticated mode: AES-256-GCM or ChaCha20-Poly1305.",
    ),

    # --- Protocol / transport weaknesses ------------------------------------
    Signature(
        id="TLS-OLD",
        pattern=r"\bTLSv?1\.0\b|\bTLSv?1\.1\b|\bSSLv[23]\b|SSLContext\.getInstance\(\s*[\"']SSL",
        category=Category.PROTOCOL_WEAK,
        primitive="TLS 1.0/1.1/SSLv2/SSLv3",
        severity=4,
        quantum_relevant=False,
        note="Deprecated transport versions — often pinned in legacy core-to-middleware "
             "integrations (ISO-8583 gateways, USSD aggregators) for backward compatibility.",
        migration_hint="Move to TLS 1.3 where the counterparty supports it; "
                        "flag any core-banking link stuck on TLS 1.0 for a compensating-control review.",
    ),

    # --- Key management smells ----------------------------------------------
    Signature(
        id="HARDCODED-KEY",
        pattern=r"(secret|private[_-]?key|api[_-]?key|passphrase)\s*[:=]\s*[\"'][A-Za-z0-9+/=_\-]{12,}[\"']",
        category=Category.HARDCODED_SECRET,
        primitive="Hardcoded secret/key literal",
        severity=5,
        quantum_relevant=False,
        note="A key or secret embedded directly in source is a key-management "
             "failure independent of algorithm choice — it will not survive any migration cleanly.",
        migration_hint="Move to a secrets manager / HSM / KMS with rotation; "
                        "never let PQC migration hardcode the new keys the same way the old ones were.",
    ),
    Signature(
        id="STATIC-IV",
        pattern=r"(iv|nonce)\s*[:=]\s*[\"'][A-Fa-f0-9]{8,}[\"']|new\s+byte\[\]\s*\{\s*0(,\s*0){7,}",
        category=Category.KEY_MGMT,
        primitive="Static/predictable IV or nonce",
        severity=4,
        quantum_relevant=False,
        note="A hardcoded or all-zero IV/nonce defeats the security guarantees of "
             "CBC/GCM modes regardless of key strength or PQC readiness.",
        migration_hint="Generate a fresh cryptographically random IV/nonce per operation.",
    ),
    Signature(
        id="WEAK-RANDOM",
        pattern=r"\bjava\.util\.Random\b|\bMath\.random\(\)|\brandom\.random\(\)|\bMt19937\b",
        category=Category.KEY_MGMT,
        primitive="Non-cryptographic PRNG used near crypto/key context",
        severity=3,
        quantum_relevant=False,
        note="Predictable PRNGs used for tokens, keys, or nonces are a "
             "recurring root cause of fintech breaches, independent of algorithm strength.",
        migration_hint="Use SecureRandom (Java), crypto.randomBytes (Node), "
                        "or secrets module (Python) for anything security-relevant.",
    ),

    # --- Positive signal: PQC already present -------------------------------
    Signature(
        id="PQC-PRESENT",
        pattern=r"\b(ML-KEM|ML-DSA|Kyber|Dilithium|SLH-DSA|SPHINCS\+|Falcon|CRYSTALS)\b",
        category=Category.PQC_PRESENT,
        primitive="Post-quantum primitive",
        severity=1,
        quantum_relevant=True,
        note="Post-quantum primitive already in use — this is the target "
             "state, not a finding to remediate.",
        migration_hint="Verify parameter set (e.g. ML-KEM-1024 / ML-DSA-65 for "
                        "high-assurance fintech use) and confirm the library "
                        "version tracks the finalized FIPS 203/204/205 standards, "
                        "not a pre-standardization draft (e.g. old round-3 Kyber/Dilithium APIs).",
    ),
]


def signatures_for_language(_lang: str) -> list[Signature]:
    """All signatures currently apply cross-language; hook kept for future
    per-language tuning (e.g. COBOL CALL 'DES1E' vs Java Cipher.getInstance)."""
    return SIGNATURES
