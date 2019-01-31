import CCryptoOpenSSL
import Foundation
import Bits

/// AES-256 GCM Cipher. This is the reccomended cipher mode. (see https://github.com/vapor/crypto/issues/59).
///
///     let key: Data // 32 bytes
///     let iv: Data // 12 RANDOM bytes; different for each plaintext to encrypt. MUST be passed alongside the ciphertext to the receiver.
///     let (ciphertext, tag) = try AES256GCM.encrypt("vapor", key: key, iv: iv)
///     print(ciphertext) // Encrypted Data
///     AES256GCM.decrypt(ciphertext, key: key, iv: iv, tag: tag).convert(to: String.self) // "vapor"
///
public var AES256GCM: AuthenticatedCipher { return .init(algorithm: .aes256gcm) }

/// Max Tag Length. Used for defining the size of input and output tags.
///     Redefined from OpenSSL's EVP_AEAD_MAX_TAG_LENGTH, which seems to be improperly defined on some platforms.
///     You can find the original #define here: https://github.com/libressl/libressl/blob/master/src/crypto/evp/evp.h#L1237-L1239
private let AEAD_MAX_TAG_LENGTH: Int32 = 16

/// AuthenticatedCipher supports AEAD-type ciphers. It feels a lot like 'Cipher' except that it supports the
/// AEAD tag and related validation.
public final class AuthenticatedCipher: OpenSSLStreamCipher {
    /// The `AuthenticatedCipherAlgorithm` (e.g., AES-256-GCM) to use.
    public let algorithm: OpenSSLCipherAlgorithm

    /// Internal OpenSSL `EVP_CIPHER_CTX` context.
    public let ctx: OpaquePointer

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
    public init(algorithm: AuthenticatedCipherAlgorithm) {
        self.algorithm = algorithm
        self.ctx = EVP_CIPHER_CTX_new().convert()
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
    public func encrypt(_ data: LosslessDataConvertible, key: LosslessDataConvertible, iv: LosslessDataConvertible) throws -> (ciphertext: Data, tag: Data) {
        var buffer = Data()

        try reset(key: key, iv: iv, mode: .encrypt)
        try update(data: data, into: &buffer)
        try finish(into: &buffer)

        let tag = try getTag()

        return (ciphertext: buffer, tag: tag)
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
    public func decrypt(_ data: LosslessDataConvertible, key: LosslessDataConvertible, iv: LosslessDataConvertible, tag: LosslessDataConvertible) throws -> Data {
        var buffer = Data()

        try reset(key: key, iv: iv, mode: .decrypt)
        try update(data: data, into: &buffer)
        try setTag(tag)
        try finish(into: &buffer)

        return buffer
    }

    /// Gets the Tag from the CIPHER_CTX struct.
    ///
    /// - note: This _must_ be called after `finish()` to retrieve the generated tag.
    ///
    /// - throws: `CryptoError` if tag retrieval fails
    public func getTag() throws -> Data {
        var buffer = Data(count: Int(AEAD_MAX_TAG_LENGTH))

        guard buffer.withMutableByteBuffer({ EVP_CIPHER_CTX_ctrl(ctx.convert(), EVP_CTRL_GCM_GET_TAG, AEAD_MAX_TAG_LENGTH, $0.baseAddress!) }) == 1 else {
            throw CryptoError.openssl(identifier: "EVP_CIPHER_CTX_ctrl", reason: "Failed getting tag (EVP_CTRL_CCM_GET_TAG).")
        }

        return buffer
    }

    /// Sets the Tag in the CIPHER_CTX struct.
    ///
    /// - note: This _must_ be called before `finish()` to set the tag.
    ///
    /// - throws: `CryptoError` if tag set fails
    public func setTag(_ tag: LosslessDataConvertible) throws {
        var buffer = tag.convertToData()

        /// Require that the tag length is full-sized. Although it is possible to use the leftmost bytes of a tag,
        /// shorter tags pose both a buffer size risk as well as an attack risk.
        guard buffer.count == AEAD_MAX_TAG_LENGTH else {
            throw CryptoError.openssl(identifier: "EVP_CIPHER_CTX_ctrl", reason: "Tag length too short: \(buffer.count) != \(AEAD_MAX_TAG_LENGTH) (AEAD_MAX_TAG_LENGTH).")
        }

        guard buffer.withMutableByteBuffer({ EVP_CIPHER_CTX_ctrl(ctx.convert(), EVP_CTRL_GCM_SET_TAG, AEAD_MAX_TAG_LENGTH, $0.baseAddress!) }) == 1 else {
            throw CryptoError.openssl(identifier: "EVP_CIPHER_CTX_ctrl", reason: "Failed setting tag (EVP_CTRL_GCM_SET_TAG).")
        }
    }

    /// Cleans up and frees the allocated OpenSSL cipher context.
    deinit {
        EVP_CIPHER_CTX_free(ctx.convert())
    }
}
