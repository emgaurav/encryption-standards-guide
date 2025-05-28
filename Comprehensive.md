# Comprehensive Encryption & Hashing Security Reference

## Table of Contents
- [Algorithm Rankings](#algorithm-rankings)
- [Symmetric Encryption](#symmetric-encryption)
- [Asymmetric Encryption](#asymmetric-encryption)
- [Hashing Algorithms](#hashing-algorithms)
- [Key Derivation Functions](#key-derivation-functions)
- [Message Authentication](#message-authentication)
- [Key Exchange Protocols](#key-exchange-protocols)
- [Post-Quantum Cryptography](#post-quantum-cryptography)
- [Performance Metrics](#performance-metrics)
- [Security Implementation Matrix](#security-implementation-matrix)
- [Compliance & Standards](#compliance--standards)

## Algorithm Rankings

### Overall Security Rating (2025)

#### Symmetric Encryption
| Rank | Algorithm | Security Score | Performance | Adoption | Recommendation |
|------|-----------|---------------|-------------|----------|----------------|
| 1 | AES-256-GCM | 10/10 | 9/10 | 10/10 | ✅ **Primary Choice** |
| 2 | ChaCha20-Poly1305 | 10/10 | 8/10 | 8/10 | ✅ **Mobile/IoT Preferred** |
| 3 | AES-256-OCB | 10/10 | 9/10 | 5/10 | ✅ **High Performance** |
| 4 | Salsa20-Poly1305 | 9/10 | 8/10 | 6/10 | ⚠️ **Specialized Use** |
| 5 | AES-256-CBC+HMAC | 8/10 | 7/10 | 9/10 | ⚠️ **Legacy Systems** |

#### Asymmetric Encryption
| Rank | Algorithm | Security Score | Performance | Adoption | Recommendation |
|------|-----------|---------------|-------------|----------|----------------|
| 1 | Ed25519 | 10/10 | 10/10 | 8/10 | ✅ **Signatures** |
| 2 | X25519 | 10/10 | 10/10 | 8/10 | ✅ **Key Exchange** |
| 3 | NIST P-384 | 9/10 | 7/10 | 9/10 | ✅ **Enterprise** |
| 4 | RSA-3072 | 8/10 | 4/10 | 10/10 | ⚠️ **Legacy Support** |
| 5 | secp256k1 | 8/10 | 8/10 | 7/10 | ⚠️ **Blockchain Only** |

#### Hashing Algorithms
| Rank | Algorithm | Security Score | Performance | Adoption | Recommendation |
|------|-----------|---------------|-------------|----------|----------------|
| 1 | BLAKE3 | 10/10 | 10/10 | 6/10 | ✅ **New Projects** |
| 2 | SHA-3 (Keccak) | 10/10 | 7/10 | 7/10 | ✅ **Regulatory** |
| 3 | BLAKE2b | 10/10 | 9/10 | 7/10 | ✅ **General Purpose** |
| 4 | SHA-256 | 9/10 | 8/10 | 10/10 | ✅ **Universal** |
| 5 | SHA-512 | 9/10 | 8/10 | 8/10 | ✅ **Long Outputs** |

## Symmetric Encryption

### Tier 1: Recommended Algorithms

#### AES (Advanced Encryption Standard)
**Variants by Use Case:**
- **AES-256-GCM**: General purpose, authenticated encryption
- **AES-256-OCB**: Patent-free alternative, highest performance
- **AES-256-SIV**: Nonce-misuse resistant
- **AES-256-GCM-SIV**: Combines GCM performance with SIV robustness

**Security Parameters:**
```yaml
Key Sizes: 128, 192, 256 bits (256 recommended)
Block Size: 128 bits
IV/Nonce: 96 bits (GCM), 128 bits (others)
Performance: 1.2-2.5 GB/s (hardware accelerated)
Security Margin: High (no practical attacks)
```

**Implementation Example:**
```python
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, AESOCB3, AESSIV
import os

# AES-GCM (most common)
key = AESGCM.generate_key(bit_length=256)
aead_gcm = AESGCM(key)
nonce = os.urandom(12)
ciphertext = aead_gcm.encrypt(nonce, data, associated_data)

# AES-OCB (highest performance)
aead_ocb = AESOCB3(key)
nonce_ocb = os.urandom(12)
ciphertext = aead_ocb.encrypt(nonce_ocb, data, associated_data)

# AES-SIV (nonce-misuse resistant)
aead_siv = AESSIV(key)
ciphertext = aead_siv.encrypt(data, [associated_data])
```

#### ChaCha20-Poly1305
**Advantages:**
- No side-channel vulnerabilities
- Superior performance on mobile/ARM
- Constant-time implementation easier
- Patent-free

**Security Parameters:**
```yaml
Key Size: 256 bits
Nonce: 96 bits (12 bytes)
Performance: 800 MB/s - 1.5 GB/s
Security Margin: Very high
Standardization: RFC 8439, TLS 1.3
```

#### XChaCha20-Poly1305
**Enhanced Variant:**
- 192-bit nonce (vs 96-bit ChaCha20)
- Eliminates nonce collision concerns
- Same security properties as ChaCha20

### Tier 2: Specialized Algorithms

#### Salsa20/XSalsa20
- **Use Case**: Streaming applications, low-latency requirements
- **Performance**: Excellent on older hardware
- **Status**: Superseded by ChaCha20 for new projects

#### Serpent-256
- **Use Case**: Ultra-high security requirements
- **Security Margin**: Highest among AES finalists
- **Performance**: ~100 MB/s (software-only)

### Corner Cases & Advanced Considerations

#### Nonce Management Strategies
```python
# Deterministic nonce (SIV mode)
from cryptography.hazmat.primitives.ciphers.aead import AESSIV
key = AESSIV.generate_key(bit_length=512)  # 256-bit key + 256-bit MAC key
aead = AESSIV(key)
# No nonce needed - deterministic based on plaintext and AAD

# Counter-based nonce
import struct
counter = 1
nonce = struct.pack('<Q', counter) + os.urandom(4)  # 8-byte counter + 4-byte random
```

## Asymmetric Encryption

### Tier 1: Modern Elliptic Curves

#### Curve25519 Family
**Ed25519 (Signatures):**
```python
from cryptography.hazmat.primitives.asymmetric import ed25519

private_key = ed25519.Ed25519PrivateKey.generate()
signature = private_key.sign(message)
public_key = private_key.public_key()
# Verification
public_key.verify(signature, message)  # Raises exception if invalid
```

**X25519 (Key Exchange):**
```python
from cryptography.hazmat.primitives.asymmetric import x25519

# Alice
alice_private = x25519.X25519PrivateKey.generate()
alice_public = alice_private.public_key()

# Bob
bob_private = x25519.X25519PrivateKey.generate()
bob_public = bob_private.public_key()

# Shared secret
alice_shared = alice_private.exchange(bob_public)
bob_shared = bob_private.exchange(alice_public)
# alice_shared == bob_shared
```

**Security Properties:**
- **Security Level**: ~128-bit
- **Performance**: 10,000+ operations/second
- **Side-Channel Resistance**: Excellent
- **Standardization**: RFC 7748, widespread adoption

#### NIST Curves (P-256, P-384, P-521)
**P-384 Recommended:**
```python
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes

private_key = ec.generate_private_key(ec.SECP384R1())
signature = private_key.sign(message, ec.ECDSA(hashes.SHA384()))
```

**Comparison Matrix:**
| Curve | Security Level | Key Size | Signature Size | Performance | NSA Suite B |
|-------|---------------|----------|---------------|-------------|-------------|
| P-256 | ~128-bit | 32 bytes | 64 bytes | High | ✅ |
| P-384 | ~192-bit | 48 bytes | 96 bytes | Medium | ✅ |
| P-521 | ~256-bit | 66 bytes | 132 bytes | Lower | ✅ |

### Tier 2: Specialized Curves

#### secp256k1 (Bitcoin Curve)
- **Use Case**: Blockchain, cryptocurrency
- **Properties**: Koblitz curve, deterministic signatures (RFC 6979)
- **Caution**: Use only for blockchain applications

#### Brainpool Curves
- **Use Case**: European regulatory compliance
- **Variants**: brainpoolP256r1, brainpoolP384r1, brainpoolP512r1
- **Status**: Good alternative to NIST curves

### RSA (Legacy Support)

#### Minimum Security Standards
```python
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes

# Key generation (3072-bit minimum for new systems)
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=3072  # or 4096 for higher security
)

# OAEP padding for encryption
ciphertext = public_key.encrypt(
    plaintext,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

# PSS padding for signatures
signature = private_key.sign(
    message,
    padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH
    ),
    hashes.SHA256()
)
```

**RSA Key Size Recommendations:**
| Year | Minimum | Recommended | High Security |
|------|---------|-------------|---------------|
| 2025 | 2048-bit | 3072-bit | 4096-bit |
| 2030 | 3072-bit | 4096-bit | 8192-bit |

## Hashing Algorithms

### Tier 1: Modern Hash Functions

#### BLAKE3
**Advantages:**
- Parallelizable (multi-threaded)
- Extremely fast (3+ GB/s)
- Tree-based construction
- Multiple output lengths

```python
import blake3

# Standard hashing
hasher = blake3.blake3()
hasher.update(b"data")
digest = hasher.digest()

# Keyed hashing (MAC)
keyed_hasher = blake3.blake3(key=key)
keyed_hasher.update(b"data")
mac = keyed_hasher.digest()

# Extendable output
xof = blake3.blake3(b"data").digest(length=64)  # 64-byte output
```

#### BLAKE2 Family
**BLAKE2b (64-bit platforms):**
- Output: 1-64 bytes
- Performance: ~1 GB/s
- Features: Keyed hashing, personalization, tree hashing

**BLAKE2s (32-bit platforms):**
- Output: 1-32 bytes
- Optimized for 32-bit architectures

```python
from cryptography.hazmat.primitives import hashes
import hashlib

# BLAKE2b
digest = hashes.Hash(hashes.BLAKE2b(64))
digest.update(b"data")
result = digest.finalize()

# BLAKE2 with key (HMAC replacement)
keyed_hash = hashlib.blake2b(b"data", key=b"secret_key")
```

#### SHA-3 (Keccak)
**Variants:**
- SHA3-224, SHA3-256, SHA3-384, SHA3-512
- SHAKE128, SHAKE256 (extendable output)

```python
from cryptography.hazmat.primitives import hashes

# Standard SHA-3
digest = hashes.Hash(hashes.SHA3_256())
digest.update(b"data")
result = digest.finalize()

# SHAKE (extendable output)
shake = hashes.Hash(hashes.SHAKE256(32))  # 32-byte output
shake.update(b"data")
result = shake.finalize()
```

### Tier 2: Established Standards

#### SHA-2 Family
**Still Recommended:**
- SHA-256: Most widely adopted
- SHA-512: Better performance on 64-bit systems
- SHA-384: Truncated SHA-512

**Performance Comparison:**
| Algorithm | Speed (MB/s) | Security Level | Hardware Support |
|-----------|-------------|---------------|------------------|
| SHA-256 | 400 | 128-bit | Excellent |
| SHA-512 | 600 | 256-bit | Good |
| BLAKE2b | 1000 | 256-bit | Software |
| BLAKE3 | 3000+ | 256-bit | Software |

## Key Derivation Functions

### Password-Based KDFs

#### Argon2 (Winner of Password Hashing Competition)
**Variants:**
- **Argon2id**: Recommended (hybrid of Argon2i and Argon2d)
- **Argon2i**: Side-channel resistant
- **Argon2d**: Maximum resistance to GPU attacks

```python
import argon2

# Production configuration
ph = argon2.PasswordHasher(
    time_cost=3,          # iterations
    memory_cost=65536,    # 64 MB
    parallelism=4,        # threads
    hash_len=32,          # output length
    salt_len=16,          # salt length
    encoding='utf-8',
    type=argon2.Type.ID   # Argon2id
)

hash_result = ph.hash("password")
ph.verify(hash_result, "password")
```

**Parameter Tuning Guide:**
| Security Level | Memory (KB) | Time Cost | Parallelism | Total Time |
|---------------|-------------|-----------|-------------|------------|
| Minimum | 32768 (32MB) | 2 | 1 | ~50ms |
| Recommended | 65536 (64MB) | 3 | 4 | ~100ms |
| High Security | 131072 (128MB) | 4 | 8 | ~200ms |

#### scrypt
```python
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
import os

salt = os.urandom(16)
kdf = Scrypt(
    algorithm=hashes.SHA256(),
    length=32,
    salt=salt,
    n=2**16,    # CPU/memory cost (65536)
    r=8,        # block size
    p=1,        # parallelization
)
key = kdf.derive(b"password")
```

#### PBKDF2 (Legacy, use only when required)
```python
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=salt,
    iterations=600000,  # OWASP recommendation 2023
)
```

### Key-Based KDFs

#### HKDF (HMAC-based KDF)
```python
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# Extract-and-Expand
hkdf = HKDF(
    algorithm=hashes.SHA256(),
    length=32,
    salt=salt,
    info=b"application context",
)
derived_key = hkdf.derive(source_key_material)
```

## Message Authentication

### MAC Algorithm Rankings

| Rank | Algorithm | Security | Performance | Use Case |
|------|-----------|----------|-------------|----------|
| 1 | BLAKE3 (keyed) | 10/10 | 10/10 | New projects |
| 2 | HMAC-SHA256 | 9/10 | 8/10 | Universal |
| 3 | Poly1305 | 10/10 | 9/10 | With ChaCha20 |
| 4 | GMAC | 9/10 | 9/10 | With AES-GCM |
| 5 | HMAC-SHA3 | 10/10 | 7/10 | Regulatory |

### Implementation Examples

#### HMAC
```python
from cryptography.hazmat.primitives import hmac, hashes

h = hmac.HMAC(key, hashes.SHA256())
h.update(b"message")
signature = h.finalize()

# Verification
h2 = hmac.HMAC(key, hashes.SHA256())
h2.update(b"message")
h2.verify(signature)  # Raises exception if invalid
```

#### Poly1305
```python
from cryptography.hazmat.primitives.poly1305 import Poly1305

p = Poly1305(key)  # 32-byte key
p.update(b"message")
tag = p.finalize()

# Verification
p2 = Poly1305(key)
p2.update(b"message")
p2.verify(tag)
```

## Key Exchange Protocols

### Modern Protocols

#### Elliptic Curve Diffie-Hellman (ECDH)
```python
from cryptography.hazmat.primitives.asymmetric import x25519

# Key exchange with X25519
alice_private = x25519.X25519PrivateKey.generate()
bob_private = x25519.X25519PrivateKey.generate()

alice_public = alice_private.public_key()
bob_public = bob_private.public_key()

# Both parties compute the same shared secret
shared_secret_alice = alice_private.exchange(bob_public)
shared_secret_bob = bob_private.exchange(alice_public)
```

#### Noise Protocol Framework
**Modern Handshake Patterns:**
- Noise_XX: Mutual authentication
- Noise_IK: Known recipient
- Noise_N: Anonymous sender

### Protocol Security Comparison

| Protocol | Forward Secrecy | Authentication | Resistance to Quantum |
|----------|----------------|---------------|----------------------|
| ECDH-X25519 | ✅ | External | ❌ |
| RSA | ❌ | ✅ | ❌ |
| Noise_XX | ✅ | ✅ | ❌ |
| NewHope (PQ) | ✅ | External | ✅ |

## Post-Quantum Cryptography

### NIST Standardized Algorithms (2024)

#### Key Encapsulation Mechanisms (KEMs)
**ML-KEM (Kyber):**
```yaml
Variants: ML-KEM-512, ML-KEM-768, ML-KEM-1024
Security Levels: 1, 3, 5 (AES equivalent)
Key Sizes: 800B, 1184B, 1568B
Ciphertext: 768B, 1088B, 1568B
Performance: Very fast
```

#### Digital Signatures
**ML-DSA (Dilithium):**
```yaml
Variants: ML-DSA-44, ML-DSA-65, ML-DSA-87
Security Levels: 2, 3, 5
Public Key: 1312B, 1952B, 2592B
Signature: 2420B, 3293B, 4595B
Performance: Fast signing, slow verification
```

**SLH-DSA (SPHINCS+):**
```yaml
Variants: SLH-DSA-128s, SLH-DSA-128f, etc.
Security: Hash-based (conservative)
Signatures: 7856B (small), 17088B (fast)
Performance: Slow signing, fast verification
```

### Implementation Readiness

#### Hybrid Approaches (Recommended)
```python
# Conceptual hybrid implementation
def hybrid_key_exchange():
    # Classical ECDH
    classical_shared = ecdh_x25519()
    
    # Post-quantum KEM
    pq_shared = ml_kem_768()
    
    # Combine both secrets
    combined_secret = hkdf_expand(classical_shared + pq_shared)
    return combined_secret
```

### Migration Timeline
- **2025**: Begin planning and testing
- **2026-2027**: Hybrid implementations
- **2028-2030**: Full migration for critical systems
- **2030+**: Classical algorithms deprecated

## Performance Metrics

### Comprehensive Benchmarks (Modern CPU - Intel i7-12700K)

#### Symmetric Encryption Throughput
| Algorithm | Encryption (MB/s) | Decryption (MB/s) | Key Setup | Memory |
|-----------|-------------------|-------------------|-----------|---------|
| AES-256-GCM | 2400 | 2400 | <1μs | 1KB |
| ChaCha20-Poly1305 | 1500 | 1500 | <1μs | 1KB |
| AES-256-OCB | 2800 | 2800 | <1μs | 1KB |
| XChaCha20-Poly1305 | 1400 | 1400 | <1μs | 1KB |

#### Asymmetric Operations (ops/second)
| Algorithm | Key Gen | Sign/Encrypt | Verify/Decrypt |
|-----------|---------|--------------|---------------|
| Ed25519 | 15,000 | 25,000 | 10,000 |
| ECDSA P-256 | 8,000 | 12,000 | 5,000 |
| RSA-3072 | 5 | 1,200 | 25,000 |
| RSA-4096 | 2 | 600 | 15,000 |

#### Hash Function Performance
| Algorithm | Throughput (MB/s) | Latency (ns/byte) | Memory |
|-----------|-------------------|-------------------|---------|
| BLAKE3 | 3200 | 0.31 | 1KB |
| BLAKE2b | 1100 | 0.91 | 1KB |
| SHA-256 | 450 | 2.22 | 1KB |
| SHA-3-256 | 200 | 5.00 | 1KB |

#### Password Hashing (target: 100ms)
| Algorithm | Memory | Time | Ops/sec | GPU Resistance |
|-----------|--------|------|---------|---------------|
| Argon2id | 64MB | 100ms | 10 | Excellent |
| scrypt | 32MB | 100ms | 10 | Good |
| bcrypt | 4KB | 100ms | 10 | Poor |
| PBKDF2 | 1KB | 100ms | 10 | Very Poor |

## Security Implementation Matrix

### Use Case Recommendations

#### Web Applications
```yaml
HTTPS/TLS:
  Cipher Suites: TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256
  Key Exchange: X25519, ECDH P-384
  Certificates: Ed25519 or ECDSA P-384
  
Session Management:
  Tokens: JWT with Ed25519 signatures
  Encryption: AES-256-GCM
  CSRF: HMAC-SHA256
  
Database:
  At Rest: AES-256-GCM
  In Transit: TLS 1.3
  Keys: External key management (HSM/KMS)
```

#### Mobile Applications
```yaml
Preferred Algorithms:
  Symmetric: ChaCha20-Poly1305
  Asymmetric: Ed25519, X25519
  Hashing: BLAKE2b
  
Storage:
  iOS: Keychain Services + AES-256-GCM
  Android: Android Keystore + AES-256-GCM
  
Communication:
  Certificate Pinning: ECDSA P-256
  API Security: HMAC-SHA256 or Ed25519 signatures
```

#### IoT/Embedded Systems
```yaml
Constrained Devices:
  Symmetric: AES-128-GCM (hardware), ChaCha20 (software)
  Asymmetric: Ed25519, X25519
  Hashing: BLAKE2s
  
Memory Optimization:
  Avoid: RSA, large symmetric keys
  Prefer: Curve25519 family, stream ciphers
  
Power Consumption:
  Best: Hardware-accelerated AES
  Alternative: ChaCha20 for software-only
```

#### Blockchain/Cryptocurrency
```yaml
Digital Signatures:
  Bitcoin: secp256k1 + ECDSA
  Ethereum: secp256k1 + ECDSA
  Modern: Ed25519 (Solana, Cardano)
  
Hashing:
  Bitcoin: SHA-256 (double)
  Ethereum: Keccak-256
  Modern: BLAKE2b or BLAKE3
  
Zero-Knowledge Proofs:
  Hash Functions: Poseidon, MiMC
  Commitment Schemes: Pedersen, KZG
```

### Threat Model Considerations

#### High-Security Environments
```yaml
Algorithms:
  Minimum Key Sizes: AES-256, RSA-4096, P-384
  Preferred: ChaCha20-Poly1305, Ed25519, BLAKE3
  Avoid: Any algorithm with known weaknesses
  
Implementation:
  Side-Channel Protection: Constant-time implementations
  Hardware Security: HSMs, secure enclaves
  Key Management: Hardware-backed, regular rotation
  
Compliance:
  FIPS 140-2 Level 3+
  Common Criteria EAL 4+
  Regular security audits
```

## Compliance & Standards

### Government & Military

#### NIST Recommendations (2025)
```yaml
Approved Algorithms:
  Symmetric: AES (all modes), ChaCha20-Poly1305
  Asymmetric: RSA (2048+), ECDSA (P-256+), Ed25519
  Hashing: SHA-2, SHA-3, BLAKE2
  
Deprecated/Restricted:
  MD5, SHA-1: Prohibited
  DES, 3DES: Legacy only
  RSA-1024: Prohibited
```

#### NSA Suite B (Updated)
```yaml
Secret Level:
  Encryption: AES-256
  Signing: ECDSA P-384
  Key Exchange: ECDH P-384
  Hashing: SHA-384
  
Top Secret:
  Encryption: AES-256
  Signing: ECDSA P-384 or Ed25519
  Key Exchange: ECDH P-384 or X25519
  Hashing: SHA-384 or BLAKE2
```

### Industry Standards

#### Payment Card Industry (PCI DSS)
```yaml
Minimum Requirements:
  Symmetric: AES-256
  Asymmetric: RSA-2048, ECDSA P-256
  Hashing: SHA-256
  
Key Management:
  Hardware Security Modules (HSMs)
  Regular key rotation
  Secure key escrow
```

#### GDPR Data Protection
```yaml
Recommended Encryption:
  Personal Data: AES-256-GCM
  Pseudonymization: HMAC-SHA256
  Right to Erasure: Cryptographic deletion
  
Key Management:
  Data Controller: Separate encryption keys
  Data Processor: Limited key access
  Cross-Border: Additional protections
```

### Implementation Security Checklist

#### Development Phase
- [ ] Use established cryptographic libraries
- [ ] Enable compiler security features (-fstack-protector, -D_FORTIFY_SOURCE)
- [ ] Implement constant-time operations
- [ ] Use secure random number generators
- [ ] Validate all inputs before cryptographic operations
- [ ] Implement proper error handling (avoid oracle attacks)
- [ ] Use authenticated encryption modes
- [ ] Implement proper key lifecycle management

#### Deployment Phase
- [ ] Regular security audits and penetration testing
- [ ] Monitor for cryptographic vulnerabilities
- [ ] Implement crypto-agility for algorithm migration
- [ ] Use hardware security modules for high-value keys
- [ ] Implement proper logging and monitoring
- [ ] Regular backup and disaster recovery testing
- [ ] Staff training on cryptographic best practices

#### Operational Phase
- [ ] Regular key rotation schedule
- [ ] Algorithm deprecation planning
- [ ] Performance monitoring and optimization
- [ ] Compliance audit preparation
- [ ] Incident response procedures
- [ ] Cryptographic inventory management

---

## Quick Reference

### OpenSSL Command Examples
```bash
# Generate various key types
openssl genpkey -algorithm Ed25519 -out ed25519.pem
openssl genpkey -algorithm X25519 -out x25519.pem
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out rsa3072.pem

# Encrypt with different algorithms
openssl enc -aes-256-gcm -pbkdf2 -in plaintext.txt -out encrypted.bin
openssl enc -chacha20-poly1305 -pbkdf2 -in plaintext.txt -out encrypted.bin

# Hash with different algorithms
echo -n "data" | openssl dgst -sha256
echo -n "data" | openssl dgst -sha3-256
echo -n "data" | openssl dgst -blake2b512
```

### Algorithm Migration Path
```yaml
Current Legacy → Recommended Modern:
  MD5 → BLAKE3 or SHA-256
  SHA-1 → SHA-256 or BLAKE2
  DES/3DES → AES-256-GCM
  RC4 → ChaCha20-Poly1305
  RSA-1024 → Ed25519 or RSA-3072
  ECDSA P-192 → Ed25519 or ECDSA P-256+
```

### Emergency Deprecation Timeline
- **Immediate**: MD5, SHA-1, DES, RC4, RSA-1024
- **2025**: Prepare post-quantum migration
- **2026**: Begin hybrid implementations
- **2030**: Classical algorithms phase-out begins


