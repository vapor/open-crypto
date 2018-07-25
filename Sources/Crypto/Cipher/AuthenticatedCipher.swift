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

public final class AuthenticatedCipher {
    /// The `CipherAlgorithm` (e.g., AES-128 ECB) to use.
    public let algorithm: AuthenticatedCipherAlgorithm

    /// Internal OpenSSL `EVP_CIPHER_CTX` context.
    let ctx: UnsafeMutablePointer<EVP_CIPHER_CTX>

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

    /// Resets / initializes the cipher algorithm context. This must be called once before calling `update(data:)`
    ///
    ///     let key: Data // 16-bytes
    ///     var aes128 = Cipher(algorithm: .aes128ecb)
    ///     try aes128.reset(key: key, mode: .encrypt)
    ///
    /// - parameters:
    ///     - key: Cipher key to use for the encryption or decryption.
    ///            This key must be an appropriate length for the cipher you are using. See `CipherAlgorithm.keySize`.
    ///     - iv: Optional initialization vector to use for the encryption or decryption.
    ///           The IV must be an appropriate length for the cipher you are using. See `CipherAlgorithm.ivSize`.
    ///     - mode: Determines whether this `Cipher` will encrypt or decrypt data.
    ///             This is set to `CipherModel.encrypt` by default.
    ///
    /// - throws: `CryptoError` if reset fails, data conversion fails, or key/iv lengths are not correct.
    public func reset(key: LosslessDataConvertible, iv: LosslessDataConvertible? = nil, mode: CipherMode = .encrypt) throws {
        let key = key.convertToData()
        let iv = iv?.convertToData()

        let keyLength = EVP_CIPHER_key_length(algorithm.c)
        guard keyLength == key.count else {
            throw CryptoError(identifier: "cipherKeySize", reason: "Invalid cipher key length \(key.count) != \(keyLength).")
        }

        let ivLength = EVP_CIPHER_iv_length(algorithm.c)
        guard (ivLength == 0 && (iv == nil || iv?.count == 0)) || (iv != nil && iv?.count == Int(ivLength)) else {
            throw CryptoError(identifier: "cipherIVSize", reason: "Invalid cipher IV length \(iv?.count ?? 0) != \(ivLength).")
        }

        guard key.withByteBuffer({ keyBuffer in
            iv.withByteBuffer { ivBuffer in
                EVP_CipherInit_ex(ctx, algorithm.c, nil, keyBuffer.baseAddress!, ivBuffer?.baseAddress, mode.rawValue)
            }
        }) == 1 else {
            throw CryptoError.openssl(identifier: "EVP_CipherInit_ex", reason: "Failed initializing cipher context.")
        }
    }

    /// Encrypts or decrypts a chunk of data into the supplied buffer.
    ///
    ///     let key: Data // 16-bytes
    ///     let aes128 = Cipher(algorithm: .aes128ecb)
    ///     try aes128.reset(key: key, mode: .encrypt)
    ///     var buffer = Data()
    ///     try aes128.update(data: "hello", into: &buffer)
    ///     try aes128.update(data: "world", into: &buffer)
    ///     print(buffer) // Partial ciphertext
    ///
    /// Note: You _must_ call `reset()` once before calling this method.
    ///
    /// - parameters:
    ///     - data: Message chunk to encrypt or decrypt.
    ///     - buffer: Mutable buffer to append newly encrypted or decrypted data to.
    /// - throws: `CryptoError` if update fails or data conversion fails.
    public func update(data: LosslessDataConvertible, into buffer: inout Data) throws {
        let input = data.convertToData()
        var chunk = Data(count: input.count + Int(algorithm.blockSize) - 1)
        var chunkLength: Int32 = 0

        guard chunk.withMutableByteBuffer({ chunkBuffer in
            input.withByteBuffer { inputBuffer in
                EVP_CipherUpdate(ctx, chunkBuffer.baseAddress!, &chunkLength, inputBuffer.baseAddress!, Int32(truncatingIfNeeded: inputBuffer.count))
            }
        }) == 1 else {
            throw CryptoError.openssl(identifier: "EVP_CipherUpdate", reason: "Failed updating cipher.")
        }
        buffer += chunk.prefix(upTo: Int(chunkLength))
    }

    /// Finalizes the encryption or decryption, appending any additional data into the supplied buffer.
    ///
    ///     let key: Data // 16-bytes
    ///     let aes128 = Cipher(algorithm: .aes128ecb)
    ///     try aes128.reset(key: key, mode: .encrypt)
    ///     var buffer = Data()
    ///     try aes128.update(data: "hello", into: &buffer)
    ///     try aes128.update(data: "world", into: &buffer)
    ///     try aes128.finish(into: &buffer)
    ///     print(buffer) // Completed ciphertext
    ///
    /// Note: You _must_ call `reset()` once and `update()` at least once before calling this method.
    ///
    /// - parameters:
    ///     - buffer: Mutable buffer to append any remaining encrypted or decrypted data to.
    /// - throws: `CryptoError` if finalization fails.
    public func finish(into buffer: inout Data) throws {
        var chunk = Data(count: Int(algorithm.blockSize))
        var chunkLength: Int32 = 0

        guard chunk.withMutableByteBuffer({ EVP_CipherFinal_ex(ctx, $0.baseAddress!, &chunkLength) }) == 1 else {
            throw CryptoError.openssl(identifier: "EVP_CipherFinal_ex", reason: "Failed finishing cipher.")
        }
        buffer += chunk.prefix(upTo: Int(chunkLength))
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
