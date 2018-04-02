import Foundation

/// PBKDF2 derives a fixed or custom length key from a password and salt.
///
/// It accepts a customizable amount of iterations to increase the algorithm weight and security.
///
/// Unlike BCrypt, the salt does not get stored in the final result,
/// meaning it needs to be generated and stored manually.
///
///     let passwordHasher = PBKDF2(algorithm: SHA512)
///     let salt = try CryptoRandom().generateData(count: 64) // Data
///     let hash = try passwordHasher.deriveKey(fromPassword: "secret", salt: salt, iterations: 15_000) // Data
///     
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
        
        func size(forAlgorithm algorithm: Digest) -> Int {
            return 0
        }
    }
    
    private let digest: Digest
    
    /// Creates a new PBKDF2 derivator based on a hashing algorithm
    public init(algorithm: DigestAlgorithm) {
        self.digest = Digest(algorithm: algorithm)
    }
    
    /// Authenticates a message using HMAC with precalculated keys (saves 50% performance)
    fileprivate func authenticate(
        _ message: Data,
        innerPadding: Data,
        outerPadding: Data
    ) throws -> Data {
        let innerPaddingHash = try self.digest.digest(innerPadding + message)
        return try self.digest.digest(outerPadding + innerPaddingHash)
    }
    
    /// Derives a key with up to `keySize` of bytes
    ///
    ///
    public func deriveKey(
        fromPassword password: Data,
        salt: Data,
        iterations: Int,
        keySize: KeySize = .digestSize
    ) throws -> Data {
        let chunkSize = numericCast(digest.algorithm.blockSize) as Int
        let digestSize = numericCast(digest.algorithm.digestSize) as Int
        let keySize = keySize.size(forAlgorithm: digest)
        
        // Check input values to be correct
        guard iterations > 0 else {
            throw CryptoError.custom(
                identifier: "noIterations",
                reason: """
                PBKDF2 was requested to iterate 0 times.
                This must be at least 1 iteration.
                10_000 is the recommended minimum for secure key derivations.
                """
            )
        }
        
        guard password.count > 0 else {
            throw CryptoError.custom(identifier: "emptySalt", reason: "The password provided to PBKDF2 was 0 bytes long")
        }
        
        guard salt.count > 0 else {
            throw CryptoError.custom(identifier: "emptySalt", reason: "The salt provided to PBKDF2 was 0 bytes long")
        }
        
        // `pow` is not available for `Int`
        guard keySize <= Int(((pow(2,32)) - 1) * Double(chunkSize)) else {
            throw CryptoError.custom(identifier: "emptySalt", reason: "The salt provided to PBKDF2 was 0 bytes long")
        }
        
        // Precalculate paddings
        var password = password
        
        // If the key is too long, hash it first
        if password.count > chunkSize {
            password = try digest.digest(password)
        }
        
        // Add padding
        if password.count < chunkSize {
            password = password + Data(repeating: 0, count: chunkSize &- password.count)
        }
        
        // XOR the information
        var outerPadding = Data(repeating: 0x5c, count: chunkSize)
        var innerPadding = Data(repeating: 0x36, count: chunkSize)
        
        outerPadding ^= password
        innerPadding ^= password
        
        // This is where all the key derivation happens
        let blocks = UInt32((keySize + digestSize - 1) / digestSize)
        var response = Data()
        response.reserveCapacity(keySize)
        
        // Salt + UInt32 (block number)
        let blockOffset = salt.count
        var salt = salt + [0,0,0,0]
        
        // Loop over all blocks
        for block in 1...blocks {
            salt.withMutableByteBuffer { buffer in
                buffer.baseAddress!.advanced(
                    by: blockOffset
                ).withMemoryRebound(
                    to: UInt32.self,
                    capacity: 1
                ) { pointer in
                    pointer.pointee = block.bigEndian
                }
            }
            
            // Iterate the first time
            var ui = try authenticate(salt, innerPadding: innerPadding, outerPadding: outerPadding)
            var u1 = ui
            
            // Continue iterating for this block
            for _ in 0..<iterations - 1 {
                u1 = try authenticate(u1, innerPadding: innerPadding, outerPadding: outerPadding)
                ui ^= u1
            }
            
            // Append the response to be returned
            response.append(contentsOf: ui)
        }
        
        // In the scenarios where the keySize is not the digestSize we have to make a slice
        if response.count > keySize {
            return Data(response[0..<keySize])
        } else {
            // Otherwise we can use a more direct return which is more performant
            return response
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
