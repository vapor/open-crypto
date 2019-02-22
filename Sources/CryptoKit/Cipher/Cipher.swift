import CCryptoOpenSSL

// MARK: Ciphers

/// AES-256 CBC Cipher. Only use this if you know what you are doing; use AES-256 GCM otherwise (see https://github.com/vapor/crypto/issues/59).
///
///     let key: Data // 32 bytes
///     let iv: Data // 16 RANDOM bytes; different for each plaintext to encrypt. MUST be passed alongside the ciphertext to the receiver.
///     let ciphertext = try AES256.encrypt("vapor", key: key, iv: iv)
///     print(ciphertext) // Encrypted Data
///     AES256.decrypt(ciphertext, key: key, iv: iv).convert(to: String.self) // "vapor"
///
public var AES256CBC: Cipher { return .init(algorithm: .aes256cbc) }

/// AES-256 CFB cipher. May not be available on all platforms.
/// Only use this if you know what you are doing; use AES-256 GCM otherwise (see https://github.com/vapor/crypto/issues/59).
public var AES256CFB128: Cipher { return .init(algorithm: .aes256cfb128) }

/// Cryptographic encryption and decryption functions for converting plaintext to and from ciphertext.
///
/// Normally, you will use the global convenience variables for encrypting and decrypting.
///
///     let ciphertext = try AES128.encrypt("vapor", key: "passwordpassword")
///     try AES128.decrypt(ciphertext, key: "passwordpassword").convert(to: String.self) // "vapor"
///
/// You may also create a `Cipher` manually.
///
///     try Cipher(algorithm: .named("aes-128-ecb").encrypt(...)
///
/// Read more about [encryption on Wikipedia](https://en.wikipedia.org/wiki/Encryption).
///
/// Read more about OpenSSL's [EVP encryption methods](https://www.openssl.org/docs/man1.1.0/crypto/EVP_EncryptInit.html).
public struct Cipher {
    /// Specifies a cipher algorithm (e.g., AES128-ECB) to be used with a `Cipher`.
    ///
    /// Common cipher algorithms are provided as static properties on this class.
    ///
    /// There are also static methods for creating `CipherAlgorithm` such as `CipherAlgorithm.named(_:)`
    public struct Algorithm {
        // MARK: Static
        
        /// Looks up a cipher function algorithm by name (e.g., "aes-128-cbc").
        /// Uses OpenSSL's `EVP_get_cipherbyname` function.
        ///
        ///     let algorithm = try CipherAlgorithm.named("aes-128-cbc")
        ///
        /// - parameters:
        ///     - name: Cipher function name
        /// - returns: Found `CipherAlgorithm`
        /// - throws: `CryptoError` if no cipher for that name is found.
        public static func named(_ name: String) throws -> Algorithm {
            guard let cipher = OpenSSLCipher.Algorithm.named(name) else {
                throw CryptoError.openssl(identifier: "EVP_get_cipherbyname", reason: "No cipher named \(name) was found.")
            }
            return .init(openssl: cipher)
        }
        
        /// AES-256 CBC cipher.
        /// Only use this if you know what you are doing; use AES-256 GCM otherwise (see https://github.com/vapor/crypto/issues/59).
        public static let aes256cbc: Algorithm = .init(openssl: .init(c: EVP_aes_256_cbc()))
        
        /// AES-256 CFB cipher. May not be available on all platforms.
        /// Only use this if you know what you are doing; use AES-256 GCM otherwise (see https://github.com/vapor/crypto/issues/59).
        public static let aes256cfb128: Algorithm = .init(openssl: .init(c: EVP_aes_256_cfb128()))
        
        /// OpenSSL `EVP_CIPHER` context.
        let openssl: OpenSSLCipher.Algorithm
        
        /// Internal init accepting a `EVP_CIPHER`.
        init(openssl: OpenSSLCipher.Algorithm) {
            self.openssl = openssl
        }
    }

    /// Internal OpenSSL `EVP_CIPHER_CTX` context.
    internal let openssl: OpenSSLCipher

    /// Creates a new `Cipher` using the supplied `CipherAlgorithm`.
    ///
    /// You can use the convenience static variables for common algorithms.
    ///
    ///     try AES128.encrypt(...)
    ///
    /// You can also use this `init(algorithm:)` method manually to supply a custom `CipherAlgorithm`.
    ///
    ///     try Cipher(algorithm: .named("aes-128-ecb").encrypt(...)
    ///
    public init(algorithm: Algorithm) {
        self.openssl = .init(algorithm: algorithm.openssl)
    }

    /// Encrypts the supplied plaintext into ciphertext. This method will call `reset(key:iv:mode:)`, `update(data:into:)`,
    /// and `finish(into:)` automatically.
    ///
    ///     let key: Data // 16-bytes
    ///     let ciphertext = try AES128.encrypt("vapor", key: key)
    ///     print(ciphertext) /// Encrypted Data
    ///
    /// - parameters:
    ///     - data: Plaintext data to encrypt.
    ///     - key: Cipher key to use for encryption.
    ///            This key must be an appropriate length for the cipher you are using. See `CipherAlgorithm.keySize`.
    ///     - iv: Optional initialization vector to use for encryption.
    ///           The IV must be an appropriate length for the cipher you are using. See `CipherAlgorithm.ivSize`.
    /// - returns: Encrypted ciphertext.
    /// - throws: `CryptoError` if reset, update, or finalization steps fail or if data conversion fails.
    public func encrypt(_ data: CryptoData, key: CryptoData, iv: CryptoData? = nil) throws -> CryptoData {
        var buffer: [UInt8] = []
        try self.openssl.reset(key: key, iv: iv, mode: .encrypt)
        try self.openssl.update(data: data, into: &buffer)
        try self.openssl.finish(into: &buffer)
        return .bytes(buffer)
    }

    /// Decrypts the supplied ciphertext back to plaintext. This method will call `reset(key:iv:mode:)`, `update(data:into:)`,
    /// and `finish(into:)` automatically.
    ///
    ///     let key: Data // 16-bytes
    ///     let ciphertext = try AES128.encrypt("vapor", key: key)
    ///     try AES128.decrypt(ciphertext, key: key) // "vapor"
    ///
    /// - parameters:
    ///     - data: Ciphertext data to decrypt.
    ///     - key: Cipher key to use for decryption.
    ///            This key must be an appropriate length for the cipher you are using. See `CipherAlgorithm.keySize`.
    ///     - iv: Optional initialization vector to use for decryption.
    ///           The IV must be an appropriate length for the cipher you are using. See `CipherAlgorithm.ivSize`.
    /// - returns: Decrypted plaintext.
    /// - throws: `CryptoError` if reset, update, or finalization steps fail or if data conversion fails.
    public func decrypt(_ data: CryptoData, key: CryptoData, iv: CryptoData? = nil) throws -> CryptoData {
        var buffer: [UInt8] = []
        try self.openssl.reset(key: key, iv: iv, mode: .decrypt)
        try self.openssl.update(data: data, into: &buffer)
        try self.openssl.finish(into: &buffer)
        return .bytes(buffer)
    }

}
