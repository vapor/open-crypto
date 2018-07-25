import CNIOOpenSSL
import Foundation
import Bits

/// AES-256 GCM Cipher. This is the reccomended cipher mode. (see https://github.com/vapor/crypto/issues/59).
///
///     let key: Data // 32 bytes
///     let iv: Data // 12 RANDOM bytes; different for each plaintext to encrypt. MUST be passed alongside the ciphertext to the receiver.
///     let ciphertext = try AES256.encrypt("vapor", key: key, iv: iv)
///     print(ciphertext) // Encrypted Data
///     AES256.decrypt(ciphertext, key: key, iv: iv).convert(to: String.self) // "vapor"
///
public var AES256GCM: AuthenticatedCipher { return .init(algorithm: .aes256gcm) }

public final class AuthenticatedCipher: OpenSSLStreamCipher {
    /// The `CipherAlgorithm` (e.g., AES-128 ECB) to use.
    public let algorithm: OpenSSLCipherAlgorithm

    /// Internal OpenSSL `EVP_CIPHER_CTX` context.
    public let ctx: UnsafeMutablePointer<EVP_CIPHER_CTX>

    /// Byte length of a GCM tag
    public static let gcmTagLength: Int = 16

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
    public init(algorithm: AuthenticatedCipherAlgorithm) {
        self.algorithm = algorithm
        self.ctx = EVP_CIPHER_CTX_new()
    }

    /// Encrypts the supplied plaintext into ciphertext. This method will call `reset(key:iv:mode:)`, `update(data:into:)`,
    /// and `finish(into:)` automatically.
    ///
    ///     let key: Data // 32-bytes
    ///     let iv: Data // 12-bytes
    ///     let (ciphertext, tag) = try AES256.encryptGCM("vapor", key: key, iv: iv)
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
    public func encrypt(_ data: LosslessDataConvertible, key: LosslessDataConvertible, iv: LosslessDataConvertible) throws -> (Data, Data) {
        var buffer = Data()

        try reset(key: key, iv: iv, mode: .encrypt)
        try update(data: data, into: &buffer)
        try finish(into: &buffer)

        let tag = try gcmTag()

        return (buffer, tag)
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
    ///     - iv: Initialization vector to use for decryption.
    ///           The IV must be an appropriate length for the cipher you are using. See `CipherAlgorithm.ivSize`.
    ///     - tag: Authentication tag for GCM-mode ciphers.
    ///           The tag must be 16 bytes
    /// - returns: Decrypted plaintext.
    /// - throws: `CryptoError` if reset, update, or finalization steps fail or if data conversion fails.
    public func decrypt(_ data: LosslessDataConvertible, key: LosslessDataConvertible, iv: LosslessDataConvertible, tag: LosslessDataConvertible) throws -> Data {
        var buffer = Data()

        try reset(key: key, iv: iv, mode: .decrypt)
        try update(data: data, into: &buffer)
        try gcmTag(tag.convertToData())
        try finish(into: &buffer)

        return buffer
    }

    /// Gets the GCM Tag from the CIPHER_CTX struct. Only usable with a GCM-mode cipher.
    ///
    /// Note: This _must_ be called after `finish()` to retrieve the generated tag.
    ///
    /// - throws: `CryptoError` if tag retrieval fails
    public func gcmTag() throws -> Data {
        var buffer = Data(count: AuthenticatedCipher.gcmTagLength)

        guard buffer.withMutableByteBuffer({ EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, Int32(AuthenticatedCipher.gcmTagLength), $0.baseAddress!) }) == 1 else {
            throw CryptoError.openssl(identifier: "EVP_CIPHER_CTX_ctrl", reason: "Failed getting tag (EVP_CTRL_CCM_GET_TAG).")
        }

        return buffer
    }

    /// Sets the GCM Tag in the CIPHER_CTX struct. Only usable with a GCM-mode cipher.
    ///
    /// Note: This _must_ be called before `finish()` to set the tag.
    ///
    /// - throws: `CryptoError` if tag set fails
    public func gcmTag(_ tag: Data) throws {
        var buffer = tag

        guard buffer.withMutableByteBuffer({ EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, Int32(AuthenticatedCipher.gcmTagLength), $0.baseAddress!) }) == 1 else {
            throw CryptoError.openssl(identifier: "EVP_CIPHER_CTX_ctrl", reason: "Failed setting tag (EVP_CTRL_GCM_SET_TAG).")
        }
    }

    /// Cleans up and frees the allocated OpenSSL cipher context.
    deinit {
        EVP_CIPHER_CTX_cleanup(ctx)
        EVP_CIPHER_CTX_free(ctx)
    }

}
