import CCryptoOpenSSL
import Foundation

// MARK: Ciphers

/// AES-128 ECB Cipher. Deprecated (see https://github.com/vapor/crypto/issues/59).
///
///     let key: Data // 16 bytes
///     let ciphertext = try AES128.encrypt("vapor", key: key)
///     print(ciphertext) // Encrypted Data
///     AES128.decrypt(ciphertext, key: key).convert(to: String.self) // "vapor"
///
@available(*, deprecated, message: "Stream encryption in ECB mode is unsafe (see https://github.com/vapor/crypto/issues/59). Use AES256 in GCM mode instead.")
public var AES128: Cipher { return .init(algorithm: .init(c: EVP_aes_128_ecb())) }

/// AES-256 ECB Cipher. Deprecated (see https://github.com/vapor/crypto/issues/59).
///
///     let key: Data // 32 bytes
///     let ciphertext = try AES256.encrypt("vapor", key: key)
///     print(ciphertext) // Encrypted Data
///     AES256.decrypt(ciphertext, key: key).convert(to: String.self) // "vapor"
///
@available(*, deprecated, message: "Stream encryption in ECB mode is unsafe (see https://github.com/vapor/crypto/issues/59). Use AES256 in GCM mode instead.")
public var AES256: Cipher { return .init(algorithm: .init(c: EVP_aes_256_ecb())) }

/// AES-256 CBC Cipher. Only use this if you know what you are doing; use AES-256 GCM otherwise (see https://github.com/vapor/crypto/issues/59).
///
///     let key: Data // 32 bytes
///     let iv: Data // 16 RANDOM bytes; different for each plaintext to encrypt. MUST be passed alongside the ciphertext to the receiver.
///     let ciphertext = try AES256.encrypt("vapor", key: key, iv: iv)
///     print(ciphertext) // Encrypted Data
///     AES256.decrypt(ciphertext, key: key, iv: iv).convert(to: String.self) // "vapor"
///
public var AES256CBC: Cipher { return .init(algorithm: .aes256cbc) }

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
public final class Cipher: OpenSSLStreamCipher {
    /// The `CipherAlgorithm` (e.g., AES-128 ECB) to use.
    public let algorithm: OpenSSLCipherAlgorithm

    /// Internal OpenSSL `EVP_CIPHER_CTX` context.
    public let ctx: OpaquePointer

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
    public init(algorithm: CipherAlgorithm) {
        self.algorithm = algorithm
        self.ctx = EVP_CIPHER_CTX_new()
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

        try reset(key: key, iv: iv, mode: .encrypt)
        try update(data: data, into: &buffer)
        try finish(into: &buffer)

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

        try reset(key: key, iv: iv, mode: .decrypt)
        try update(data: data, into: &buffer)
        try finish(into: &buffer)
        return .bytes(buffer)
    }

    /// Frees the allocated OpenSSL cipher context.
    deinit {
        EVP_CIPHER_CTX_free(self.ctx)
    }
}
