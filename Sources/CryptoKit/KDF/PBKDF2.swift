import CCryptoOpenSSL

/// PBKDF2 derives a fixed or custom length key from a password and salt.
///
/// It accepts a customizable amount of iterations to increase the algorithm weight and security.
///
/// Unlike BCrypt, the salt does not get stored in the final result,
/// meaning it needs to be generated and stored manually.
///
///     let passwordHasher = PBKDF2(digest: SHA1)
///     let salt = try CryptoRandom().generateData(count: 64) // Data
///     let hash = try passwordHasher.deriveKey(fromPassword: "secret", salt: salt, iterations: 15_000) // Data
///     print(hash.hexEncodedString()) // 8e55fa3015da583bb51b706371aa418afc8a0a44
///
/// PBKDF2 leans on HMAC for each iteration and can use all hash functions supported in Crypto
///
/// https://en.wikipedia.org/wiki/PBKDF2
public final class PBKDF2 {
    /// The requested amount of output bytes from the key derivation
    ///
    /// In circumstances with low iterations the amount of output bytes may not be met.
    ///
    /// `digest.digestSize * iterations` is the amount of bytes stored in PBKDF2's buffer.
    /// Any data added beyond this limit
    public enum KeySize {
        case digestSize
        case fixed(Int)
        
        fileprivate func size(for digest: Digest) -> Int {
            switch self {
            case .digestSize:
                return numericCast(digest.algorithm.digestSize)
            case .fixed(let size):
                return size
            }
        }
    }
    
    /// MD4 digest powered key derivation.
    ///
    /// https://en.wikipedia.org/wiki/MD4
    public static var MD4: PBKDF2 { return .init(digest: .md4) }
    
    /// MD5 digest powered key derivation.
    ///
    /// https://en.wikipedia.org/wiki/MD5
    public static var MD5: PBKDF2 { return .init(digest: .md5) }
    
    /// SHA-1 digest powered key derivation.
    ///
    /// https://en.wikipedia.org/wiki/SHA-1
    public static var SHA1: PBKDF2 { return .init(digest: .sha1) }
    
    /// SHA-224 (SHA-2) digest powered key derivation.
    ///
    /// https://en.wikipedia.org/wiki/SHA-2
    public static var SHA224: PBKDF2 { return .init(digest: .sha224) }
    
    /// SHA-256 (SHA-2) digest powered key derivation.
    ///
    /// https://en.wikipedia.org/wiki/SHA-2
    public static var SHA256: PBKDF2 { return .init(digest: .sha256) }
    
    /// SHA-384 (SHA-2) digest powered key derivation.
    ///
    /// https://en.wikipedia.org/wiki/SHA-2
    public static var SHA384: PBKDF2 { return .init(digest: .sha384) }
    
    /// SHA-512 (SHA-2) digest powered key derivation.
    ///
    /// https://en.wikipedia.org/wiki/SHA-2
    public static var SHA512: PBKDF2 { return .init(digest: .sha512) }
    
    private let digest: Digest
    
    /// Creates a new PBKDF2 derivator based on a hashing algorithm
    public init(digest: Digest.Algorithm) {
        self.digest = .init(algorithm: digest)
    }
    
    /// Derives a key with up to `keySize` of bytes
    ///
    ///
    public func hash(
        _ password: CryptoData,
        salt: CryptoData,
        iterations: Int32,
        keySize: KeySize = .digestSize
    ) throws -> CryptoData {
        let keySize = keySize.size(for: digest)
        
        var output = [UInt8](repeating: 0, count: keySize)
        
        let res = salt.withUnsafeBytes { saltBuffer in
            return password.withUnsafeBytes { passwordBuffer in
                return output.withUnsafeMutableBytes { outputBuffer in
                    return PKCS5_PBKDF2_HMAC(
                        passwordBuffer.baseAddress?.assumingMemoryBound(to: Int8.self),
                        Int32(password.count), // password string and length
                        saltBuffer.baseAddress?.assumingMemoryBound(to: UInt8.self),
                        Int32(saltBuffer.count), // salt pointer and length
                        iterations, // Iteration count
                        self.digest.algorithm.c, // Algorithm identifier
                        Int32(keySize),
                        outputBuffer.baseAddress?.assumingMemoryBound(to: UInt8.self) // Output buffer
                    )
                }
            }
        }        
        guard res == 1 else {
            throw CryptoError.openssl(identifier: "PKCS5_PBKDF2_HMAC", reason: "Failed to hash password using PBKDF2")
        }
        
        return .bytes(output)
    }
}
