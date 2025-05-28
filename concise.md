# Encryption & Hashing Best Practices Reference

## Table of Contents
- [Symmetric Encryption](#symmetric-encryption)
- [Asymmetric Encryption](#asymmetric-encryption)
- [Hashing Algorithms](#hashing-algorithms)
- [Key Management](#key-management)
- [Implementation Guidelines](#implementation-guidelines)
- [Performance Metrics](#performance-metrics)
- [Security Considerations](#security-considerations)

## Symmetric Encryption

### Recommended Algorithms

#### AES (Advanced Encryption Standard)
- **Best Practice**: Use AES-256-GCM for new implementations
- **Key Size**: 256-bit minimum
- **Mode**: GCM (Galois/Counter Mode) for authenticated encryption
- **Performance**: ~1.2 GB/s on modern CPUs

**Use Cases:**
- Database encryption at rest
- File system encryption
- Secure communication channels
- API payload encryption

**Example Implementation:**
```python
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# AES-GCM example
key = AESGCM.generate_key(bit_length=256)
aead = AESGCM(key)
nonce = os.urandom(12)  # 96-bit nonce for GCM
ciphertext = aead.encrypt(nonce, plaintext, associated_data)
```

#### ChaCha20-Poly1305
- **Best Practice**: Alternative to AES on mobile/embedded devices
- **Performance**: Better on devices without AES hardware acceleration
- **Key Size**: 256-bit

**Use Cases:**
- Mobile applications
- IoT devices
- Systems without AES-NI support

### Corner Cases & Considerations
- **IV/Nonce Reuse**: Never reuse nonce with same key (catastrophic for GCM)
- **Padding Oracle Attacks**: Use authenticated encryption modes
- **Side-Channel Attacks**: Use constant-time implementations

## Asymmetric Encryption

### Recommended Algorithms

#### RSA
- **Minimum Key Size**: 2048-bit (3072-bit recommended for new systems)
- **Padding**: OAEP with SHA-256
- **Performance**: ~1000 operations/sec for 2048-bit

**Use Cases:**
- Digital signatures
- Key exchange
- Certificate-based authentication
- Legacy system integration

#### Elliptic Curve Cryptography (ECC)
- **Recommended Curves**: P-256, P-384, Ed25519
- **Key Size Equivalent**: 256-bit ECC ≈ 3072-bit RSA
- **Performance**: 10x faster than RSA for equivalent security

**Use Cases:**
- Modern web protocols (TLS 1.3)
- Mobile applications
- Blockchain implementations
- IoT devices

**Example Implementation:**
```python
from cryptography.hazmat.primitives.asymmetric import ed25519

# Ed25519 signing
private_key = ed25519.Ed25519PrivateKey.generate()
signature = private_key.sign(message)
public_key = private_key.public_key()
public_key.verify(signature, message)
```

## Hashing Algorithms

### Cryptographic Hashes

#### SHA-256/SHA-3
- **Use Case**: Data integrity, digital signatures, blockchain
- **Performance**: SHA-256 ~400 MB/s, SHA-3 ~200 MB/s
- **Output Size**: 256-bit

#### BLAKE2/BLAKE3
- **Use Case**: High-performance applications requiring cryptographic hashing
- **Performance**: BLAKE3 ~3 GB/s (parallelizable)
- **Security**: Equivalent to SHA-3

### Password Hashing

#### Argon2id (Recommended)
- **Parameters**: 
  - Memory: 64 MB minimum
  - Iterations: 3-4
  - Parallelism: 1-4 threads
- **Performance**: ~100ms per hash (target)

**Example Configuration:**
```python
import argon2

# Production settings
ph = argon2.PasswordHasher(
    memory_cost=65536,  # 64 MB
    time_cost=3,        # 3 iterations
    parallelism=4,      # 4 threads
    hash_len=32,        # 32 byte output
    salt_len=16         # 16 byte salt
)
```

#### scrypt/bcrypt (Alternative)
- **scrypt**: Good for memory-hard requirements
- **bcrypt**: Widely supported, CPU-hard
- **Cost Factor**: bcrypt work factor 12+ (2023 standard)

### Use Case Matrix

| Algorithm | Data Integrity | Password Storage | Digital Signatures | Key Derivation |
|-----------|---------------|------------------|-------------------|----------------|
| SHA-256   | ✅ | ❌ | ✅ | ❌ |
| Argon2id  | ❌ | ✅ | ❌ | ✅ |
| PBKDF2    | ❌ | ⚠️ | ❌ | ✅ |
| bcrypt    | ❌ | ✅ | ❌ | ❌ |

## Key Management

### Best Practices

1. **Key Rotation**
   - Symmetric keys: Rotate every 1-2 years or after exposure
   - Asymmetric keys: 2-5 years depending on key size
   - Certificate authorities: Follow industry standards

2. **Key Storage**
   - Use Hardware Security Modules (HSMs) for high-value keys
   - Environment variables for application keys (not hardcoded)
   - Key management services (AWS KMS, Azure Key Vault, HashiCorp Vault)

3. **Key Derivation**
   - Use HKDF for deriving multiple keys from master key
   - Separate keys for different purposes (encryption, authentication)

## Implementation Guidelines

### Development Checklist

- [ ] Use established cryptographic libraries (avoid custom implementations)
- [ ] Enable constant-time operations where available
- [ ] Implement proper error handling (avoid cryptographic oracles)
- [ ] Use secure random number generators
- [ ] Validate all inputs before cryptographic operations
- [ ] Implement proper key lifecycle management
- [ ] Regular security audits and penetration testing

### Common Vulnerabilities

| Vulnerability | Impact | Mitigation |
|---------------|--------|------------|
| Weak Random Seeds | Complete compromise | Use OS-provided CSPRNG |
| Time-based Side Channels | Key recovery | Constant-time implementations |
| Padding Oracle | Plaintext recovery | Authenticated encryption |
| IV/Nonce Reuse | Complete compromise | Proper nonce management |

## Performance Metrics

### Throughput Benchmarks (Typical Hardware)

| Algorithm | Encryption Speed | Decryption Speed | Key Gen Speed |
|-----------|-----------------|------------------|---------------|
| AES-256-GCM | 1.2 GB/s | 1.2 GB/s | Instant |
| ChaCha20-Poly1305 | 800 MB/s | 800 MB/s | Instant |
| RSA-2048 | 1K ops/s | 15K ops/s | 0.1 ops/s |
| Ed25519 | 10K ops/s | 5K ops/s | 10K ops/s |

### Memory Usage

| Algorithm | Memory Requirement | Notes |
|-----------|-------------------|-------|
| AES | ~1KB | Minimal memory footprint |
| Argon2id | 64+ MB | Configurable, memory-hard |
| RSA | ~8KB | Key size dependent |
| ECC | ~1KB | Much smaller than RSA |

## Security Considerations

### Compliance Requirements

- **FIPS 140-2**: AES, SHA-2, RSA, ECDSA approved algorithms
- **Common Criteria**: Evaluated implementations for high-assurance systems
- **PCI DSS**: AES-256, RSA-2048+ for payment card data
- **GDPR**: Strong encryption for personal data protection

### Risk Assessment

**High Risk Scenarios:**
- Custom cryptographic implementations
- Weak key management practices
- Legacy algorithm usage (MD5, SHA-1, DES)
- Improper random number generation

**Mitigation Strategies:**
- Regular cryptographic reviews
- Automated vulnerability scanning
- Penetration testing
- Security training for development teams

### Future Considerations

**Post-Quantum Cryptography:**
- NIST standardized algorithms (2024): Kyber, Dilithium, SPHINCS+
- Timeline: Begin planning migration by 2025
- Hybrid approaches: Classical + post-quantum during transition

---

## Quick Reference Commands

### OpenSSL Examples
```bash
# Generate AES-256-GCM encrypted file
openssl enc -aes-256-gcm -salt -in plaintext.txt -out encrypted.bin

# Generate RSA key pair
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out private.pem

# Generate Ed25519 key pair
openssl genpkey -algorithm Ed25519 -out ed25519_private.pem
```

### Validation Checklist
- ✅ Algorithm approved for intended use case
- ✅ Key size meets current security standards
- ✅ Implementation uses established libraries
- ✅ Proper error handling implemented
- ✅ Key management lifecycle defined
- ✅ Performance requirements met
- ✅ Compliance requirements satisfied

