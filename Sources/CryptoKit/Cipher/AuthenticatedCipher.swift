import CCryptoOpenSSL

/// AES-256 GCM Cipher. This is the reccomended cipher mode. (see https://github.com/vapor/crypto/issues/59).
///
///     let key: Data // 32 bytes
///     let iv: Data // 12 RANDOM bytes; different for each plaintext to encrypt. MUST be passed alongside the ciphertext to the receiver.
///     let (ciphertext, tag) = try AES256GCM.encrypt("vapor", key: key, iv: iv)
///     print(ciphertext) // Encrypted Data
///     AES256GCM.decrypt(ciphertext, key: key, iv: iv, tag: tag).convert(to: String.self) // "vapor"
///
public var AES256GCM: AuthenticatedCipher { return .init(algorithm: .aes256gcm) }

/// AuthenticatedCipher supports AEAD-type ciphers. It feels a lot like 'Cipher' except that it supports the
/// AEAD tag and related validation.
public final class AuthenticatedCipher {
    /// Specifies an authenticated cipher algorithm (e.g., AES-256-GCM) to be used with an `AuthenticatedCipher`.
    ///
    /// Common authenticated cipher algorithms are provided as static properties on this class.
    ///
    /// There are also static methods for creating `AuthenticatedCipherAlgorithm` such as `AuthenticatedCipherAlgorithm.named(_:)`
    public struct Algorithm {
        // MARK: Static
        
        /// Looks up an authenticated cipher function algorithm by name (e.g., "aes-256-gcm").
        /// Uses OpenSSL's `EVP_get_cipherbyname` function.
        ///
        ///     let algorithm = try CipherAlgorithm.named("aes-256-gcm")
        ///
        /// - parameters:
        ///     - name: Cipher function name
        /// - returns: Found `AuthenticatedCipherAlgorithm`
        /// - throws: `CryptoError` if no cipher for that name is found.
        public static func named(_ name: String) throws -> Algorithm {
            guard let cipher = OpenSSLCipher.Algorithm.named(name) else {
                throw CryptoError.openssl(identifier: "EVP_get_cipherbyname", reason: "No cipher named \(name) was found.")
            }
            return .init(openssl: cipher)
        }
        
        /// AES-256 GCM cipher. This is the recommended cipher.
        /// See the global `AES256GCM` constant on usage.
        public static let aes256gcm: Algorithm = .init(openssl: .init(c: EVP_aes_256_gcm()))
        
        /// OpenSSL `EVP_CIPHER` context.
        let openssl: OpenSSLCipher.Algorithm
        
        /// Internal init accepting a `EVP_CIPHER`.
        init(openssl: OpenSSLCipher.Algorithm) {
            self.openssl = openssl
        }
    }

    /// Internal OpenSSL `EVP_CIPHER_CTX` context.
    private let openssl: OpenSSLCipher

    /// Creates a new `Cipher` using the supplied `CipherAlgorithm`.
    ///
    /// You can use the convenience static variables for common algorithms.
    ///
    ///     try AES256GCM.encrypt(...)
    ///
    /// You can also use this `init(algorithm:)` method manually to supply a custom `CipherAlgorithm`.
    ///
    ///     try AuthenticatedCipher(algorithm: .named("aes-256-gcm").encrypt(...)
    ///
    public init(algorithm: Algorithm) {
        self.openssl = .init(algorithm: algorithm.openssl)
    }

    /// Encrypts the supplied plaintext into ciphertext. This method will call `reset(key:iv:mode:)`, `update(data:into:)`,
    /// and `finish(into:)` automatically.
    ///
    ///     let key: Data // 32-bytes
    ///     let iv: Data // 12-bytes
    ///     let (ciphertext, tag) = try AES256GCM.encrypt("vapor", key: key, iv: iv)
    ///     print(ciphertext) /// Encrypted Data
    ///     print(tag) /// GCM authentication tag
    ///
    /// - parameters:
    ///     - data: Plaintext data to encrypt.
    ///     - key: Cipher key to use for encryption.
    ///            This key must be an appropriate length for the cipher you are using. See `CipherAlgorithm.keySize`.
    ///     - iv: Initialization vector to use for encryption.
    ///           The IV must be an appropriate length for the cipher you are using. See `CipherAlgorithm.ivSize`.
    /// - returns: Encrypted ciphertext and GCM tag.
    /// - throws: `CryptoError` if reset, update, finalization or tag retrieval steps fail or if data conversion fails.
    public func encrypt(_ data: CryptoData, key: CryptoData, iv: CryptoData) throws -> (ciphertext: CryptoData, tag: CryptoData) {
        var buffer: [UInt8] = []
        try self.openssl.reset(key: key, iv: iv, mode: .encrypt)
        try self.openssl.update(data: data, into: &buffer)
        try self.openssl.finish(into: &buffer)
        return try (ciphertext: .bytes(buffer), tag: self.openssl.getTag())
    }

    /// Decrypts the supplied ciphertext back to plaintext. This method will call `reset(key:iv:mode:)`, `update(data:into:)`,
    /// and `finish(into:)` automatically.
    ///
    ///     let key: Data // 32-bytes
    ///     let iv: Data // 12-bytes
    ///     let (ciphertext, tag) = try AES256GCM.encrypt("vapor", key: key, iv: iv)
    ///     try AES256GCM.decrypt(ciphertext, key: key, iv: iv, tag: tag) // "vapor"
    ///
    /// - parameters:
    ///     - data: Ciphertext data to decrypt.
    ///     - key: Cipher key to use for decryption.
    ///            This key must be an appropriate length for the cipher you are using. See `CipherAlgorithm.keySize`.
    ///     - iv: Initialization vector to use for decryption.
    ///           The IV must be an appropriate length for the cipher you are using. See `CipherAlgorithm.ivSize`.
    ///     - tag: Authentication tag for GCM-mode ciphers.
    ///           The tag must be 16 bytes
    /// - returns: Decrypted plaintext.
    /// - throws: `CryptoError` if reset, update, or finalization steps fail or if data conversion fails.
    public func decrypt(_ data: CryptoData, key: CryptoData, iv: CryptoData, tag: CryptoData) throws -> CryptoData {
        var buffer: [UInt8] = []
        try self.openssl.reset(key: key, iv: iv, mode: .decrypt)
        try self.openssl.update(data: data, into: &buffer)
        try self.openssl.setTag(tag)
        try self.openssl.finish(into: &buffer)
        return .bytes(buffer)
    }
}
