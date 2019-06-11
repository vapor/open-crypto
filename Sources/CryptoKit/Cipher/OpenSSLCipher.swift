import CCryptoOpenSSL

/// Available cipher modes. Either `encrypt` or `decrypt`.
///
/// Used when calling `reset` on a `Cipher`.
public enum CipherMode: Int32 {
    /// Encrypts arbitrary data to encrypted ciphertext.
    case encrypt = 1

    /// Decrypts encrypted ciphertext back to its original value.
    case decrypt = 0
}

/// OpenSSLStreamCipher is a protocol representing a higher-level interface for managing various OpenSSL stream ciphers.
final class OpenSSLCipher {
    /// OpenSSLCipherAlgorithm represents a common set of properties shared by
    /// OpenSSL cipher algorithms.
    final class Algorithm {
        /// OpenSSL `EVP_CIPHER` context.
        var c: UnsafePointer<EVP_CIPHER>
        
        static func named(_ name: String) -> Algorithm? {
            guard let cipher = EVP_get_cipherbyname(name) else {
                return nil
            }
            return .init(c: cipher)
        }
        
        /// An initializer accepting the EVP_CIPHER to work with
        init(c:  UnsafePointer<EVP_CIPHER>) {
            self.c = c
        }
        
        /// See `OpenSSLCipherAlgorithm`
        public var type: Int32 {
            return EVP_CIPHER_type(self.c)
        }
        
        /// See `OpenSSLCipherAlgorithm`
        public var keySize: Int32 {
            return EVP_CIPHER_key_length(self.c)
        }
        
        /// See `OpenSSLCipherAlgorithm`
        public var ivSize: Int32 {
            return EVP_CIPHER_iv_length(self.c)
        }
        
        /// See `OpenSSLCipherAlgorithm`
        public var blockSize: Int32 {
            return EVP_CIPHER_block_size(self.c)
        }
    }
    
    /// The OpenSSLCipherAlgorithm this stream cipher is interacting with
    var algorithm: Algorithm
    
    /// The OpenSSL Cipher Stream Context
    private var ctx: UnsafeMutablePointer<EVP_CIPHER_CTX>
    
    init(algorithm: Algorithm) {
        self.algorithm = algorithm
        self.ctx = EVP_CIPHER_CTX_new()
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
    func reset(key: CryptoData, iv: CryptoData? = nil, mode: CipherMode = .encrypt) throws {
        let keyLength = EVP_CIPHER_key_length(self.algorithm.c)
        guard keyLength == key.count else {
            throw CryptoError(identifier: "cipherKeySize", reason: "Invalid cipher key length \(key.count) != \(keyLength).")
        }

        let ivLength = EVP_CIPHER_iv_length(self.algorithm.c)
        guard (ivLength == 0 && (iv == nil || iv?.count == 0)) || (iv != nil && iv?.count == Int(ivLength)) else {
            throw CryptoError(identifier: "cipherIVSize", reason: "Invalid cipher IV length \(iv?.count ?? 0) != \(ivLength).")
        }

        guard key.withUnsafeBytes({ (keyBuffer: UnsafeRawBufferPointer) -> Int32 in
            return iv.withUnsafeBytes { (ivBuffer: UnsafeRawBufferPointer?) -> Int32 in
                EVP_CipherInit_ex(
                    self.ctx,
                    self.algorithm.c,
                    nil,
                    keyBuffer.baseAddress?.assumingMemoryBound(to: UInt8.self),
                    ivBuffer?.baseAddress?.assumingMemoryBound(to: UInt8.self),
                    mode.rawValue
                )
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
    func update(data: CryptoData, into buffer: inout [UInt8]) throws {
        var chunk = [UInt8](repeating: 0, count: data.count + Int(algorithm.blockSize) - 1)
        var chunkLength: Int32 = 0

        guard chunk.withUnsafeMutableBytes({ chunkBuffer in
            data.withUnsafeBytes { inputBuffer in
                return EVP_CipherUpdate(
                    self.ctx,
                    chunkBuffer.baseAddress!.assumingMemoryBound(to: UInt8.self),
                    &chunkLength,
                    inputBuffer.baseAddress!.assumingMemoryBound(to: UInt8.self),
                    Int32(truncatingIfNeeded: inputBuffer.count)
                )
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
    func finish(into buffer: inout [UInt8]) throws {
        var chunk = [UInt8](repeating: 0, count: Int(algorithm.blockSize))
        var chunkLength: Int32 = 0

        guard chunk.withUnsafeMutableBytes({
            return EVP_CipherFinal_ex(
                ctx,
                $0.baseAddress!.assumingMemoryBound(to: UInt8.self),
                &chunkLength
            )
        }) == 1 else {
            throw CryptoError.openssl(identifier: "EVP_CipherFinal_ex", reason: "Failed finishing cipher.")
        }
        buffer += chunk.prefix(upTo: Int(chunkLength))
    }
    
    
    /// Gets the Tag from the CIPHER_CTX struct.
    ///
    /// - note: This _must_ be called after `finish()` to retrieve the generated tag.
    ///
    /// - throws: `CryptoError` if tag retrieval fails
    public func getTag() throws -> CryptoData {
        var buffer = [UInt8](repeating: 0, count: Int(AEAD_MAX_TAG_LENGTH))
        
        guard buffer.withUnsafeMutableBytes({
            EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, AEAD_MAX_TAG_LENGTH, $0.baseAddress)
        }) == 1 else {
            throw CryptoError.openssl(identifier: "EVP_CIPHER_CTX_ctrl", reason: "Failed getting tag (EVP_CTRL_CCM_GET_TAG).")
        }
        
        return .bytes(buffer)
    }
    
    /// Sets the Tag in the CIPHER_CTX struct.
    ///
    /// - note: This _must_ be called before `finish()` to set the tag.
    ///
    /// - throws: `CryptoError` if tag set fails
    public func setTag(_ tag: CryptoData) throws {
        var buffer = tag.bytes()
        
        /// Require that the tag length is full-sized. Although it is possible to use the leftmost bytes of a tag,
        /// shorter tags pose both a buffer size risk as well as an attack risk.
        guard buffer.count == AEAD_MAX_TAG_LENGTH else {
            throw CryptoError.openssl(identifier: "EVP_CIPHER_CTX_ctrl", reason: "Tag length too short: \(buffer.count) != \(AEAD_MAX_TAG_LENGTH) (AEAD_MAX_TAG_LENGTH).")
        }
        
        guard buffer.withUnsafeMutableBytes({
            EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, AEAD_MAX_TAG_LENGTH, $0.baseAddress)
        }) == 1 else {
            throw CryptoError.openssl(identifier: "EVP_CIPHER_CTX_ctrl", reason: "Failed setting tag (EVP_CTRL_GCM_SET_TAG).")
        }
    }

    
    /// Frees the allocated OpenSSL cipher context.
    deinit {
        EVP_CIPHER_CTX_free(self.ctx)
    }
}

/// Max Tag Length. Used for defining the size of input and output tags.
///     Redefined from OpenSSL's EVP_AEAD_MAX_TAG_LENGTH, which seems to be improperly defined on some platforms.
///     You can find the original #define here: https://github.com/libressl/libressl/blob/master/src/crypto/evp/evp.h#L1237-L1239
private let AEAD_MAX_TAG_LENGTH: Int32 = 16
