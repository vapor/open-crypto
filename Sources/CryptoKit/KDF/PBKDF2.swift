import Foundation
import CNIOOpenSSL
import Core

/// The requested amount of output bytes from the key derivation
///
/// In circumstances with low iterations the amount of output bytes may not be met.
///
/// `digest.digestSize * iterations` is the amount of bytes stored in PBKDF2's buffer.
/// Any data added beyond this limit
public enum PBKDF2KeySize {
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
    private let digest: Digest
    
    /// MD4 digest powered key derivation.
    ///
    /// https://en.wikipedia.org/wiki/MD4
    public static var MD4: PBKDF2 { return .init(digest: Crypto.MD4) }
    
    /// MD5 digest powered key derivation.
    ///
    /// https://en.wikipedia.org/wiki/MD5
    public static var MD5: PBKDF2 { return .init(digest: Crypto.MD5) }
    
    /// SHA-1 digest powered key derivation.
    ///
    /// https://en.wikipedia.org/wiki/SHA-1
    public static var SHA1: PBKDF2 { return .init(digest: Crypto.SHA1) }
    
    /// SHA-224 (SHA-2) digest powered key derivation.
    ///
    /// https://en.wikipedia.org/wiki/SHA-2
    public static var SHA224: PBKDF2 { return .init(digest: Crypto.SHA224) }
    
    /// SHA-256 (SHA-2) digest powered key derivation.
    ///
    /// https://en.wikipedia.org/wiki/SHA-2
    public static var SHA256: PBKDF2 { return .init(digest: Crypto.SHA256) }
    
    /// SHA-384 (SHA-2) digest powered key derivation.
    ///
    /// https://en.wikipedia.org/wiki/SHA-2
    public static var SHA384: PBKDF2 { return .init(digest: Crypto.SHA384) }
    
    /// SHA-512 (SHA-2) digest powered key derivation.
    ///
    /// https://en.wikipedia.org/wiki/SHA-2
    public static var SHA512: PBKDF2 { return .init(digest: Crypto.SHA512) }
    
    /// Creates a new PBKDF2 derivator based on a hashing algorithm
    public init(digest: Digest) {
        self.digest = digest
    }
    
    /// Derives a key with up to `keySize` of bytes
    ///
    ///
    public func hash(
        _ password: String,
        salt: LosslessDataConvertible,
        iterations: Int32,
        keySize: PBKDF2KeySize = .digestSize
    ) throws -> Data {
        let keySize = keySize.size(for: digest)
        let salt = try salt.convertToData()
        
        var output = Data(repeating: 0, count: keySize)
        
        return try salt.withByteBuffer { saltBuffer in
            try output.withMutableByteBuffer { outputBuffer in
                let resultCode = PKCS5_PBKDF2_HMAC(
                    password, Int32(password.count), // password string and length
                    saltBuffer.baseAddress, Int32(saltBuffer.count), // salt pointer and length
                    iterations, // Iteration count
                    self.digest.algorithm.c, // Algorithm identifier
                    Int32(keySize), outputBuffer.baseAddress // Output buffer
                )
                
                guard resultCode == 1 else {
                    throw CryptoError.openssl(identifier: "PKCS5_PBKDF2_HMAC", reason: "Failed to hash password using PBKDF2")
                }
            }
            
            return output
        }
    }
}

/// XORs the lhs bytes with the rhs bytes on the same index
///
/// Assumes and asserts lhs and rhs to have an equal count
fileprivate func ^=(lhs: inout Data, rhs: Data) {
    // These two must be equal for the PBKDF2 implementation to be correct
    assert(lhs.count == rhs.count)
    
    // Foundation does not guarantee that Data is a top-level blob
    // It may be a sliced blob with a startIndex of > 0
    var lhsIndex = lhs.startIndex
    var rhsIndex = rhs.startIndex
    
    for _ in 0..<lhs.count {
        lhs[lhsIndex] = lhs[lhsIndex] ^ rhs[rhsIndex]
        
        lhsIndex += 1
        rhsIndex += 1
    }
}
