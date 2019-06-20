import COpenCrypto

enum CipherMode: Int32 {
    case encrypt = 1
    case decrypt = 0
}

final class OpenSSLCipher {
    var algorithm: OpaquePointer
    var context: OpaquePointer

    init(algorithm: OpaquePointer) {
        self.algorithm = algorithm
        self.context = EVP_CIPHER_CTX_new()
    }

    func reset<IV>(key: SymmetricKey, iv: IV, mode: CipherMode)
        where IV: DataProtocol
    {
        guard key.bitCount == numericCast(EVP_CIPHER_key_length(self.algorithm)) * 8 else {
            fatalError("Invalid cipher key length")
        }
        guard iv.count == numericCast(EVP_CIPHER_iv_length(self.algorithm)) else {
            fatalError("Invalid cipher IV length")
        }

        guard EVP_CipherInit_ex(
            self.context,
            self.algorithm,
            nil,
            key.bytes,
            iv.copyBytes(),
            mode.rawValue
        ) == 1 else {
            fatalError("Failed initializing cipher context.")
        }
    }

    func update<Data>(data: Data, into buffer: inout [UInt8])
        where Data: DataProtocol
    {
        let data = data.copyBytes()
        var chunk = [UInt8](repeating: 0, count: data.count + numericCast(EVP_CIPHER_block_size(self.algorithm)) - 1)
        var chunkLength: Int32 = 0

        guard EVP_CipherUpdate(
            self.context,
            &chunk,
            &chunkLength,
            data,
            numericCast(data.count)
        ) == 1 else {
            fatalError("Failed updating cipher.")
        }
        buffer += chunk.prefix(upTo: Int(chunkLength))
    }

    func finish(into buffer: inout [UInt8]) {
        var chunk = [UInt8](repeating: 0, count: numericCast(EVP_CIPHER_block_size(self.algorithm)))
        var chunkLength: Int32 = 0

        guard EVP_CipherFinal_ex(
            self.context,
            &chunk,
            &chunkLength
        ) == 1 else {
            fatalError("Failed finishing cipher.")
        }
        buffer += chunk.prefix(upTo: Int(chunkLength))
    }

    func getTag() -> [UInt8] {
        var buffer = [UInt8](repeating: 0, count: Int(AEAD_MAX_TAG_LENGTH))

        guard EVP_CIPHER_CTX_ctrl(
            self.context,
            EVP_CTRL_GCM_GET_TAG,
            AEAD_MAX_TAG_LENGTH,
            &buffer
        ) == 1 else {
            fatalError("Failed getting tag (EVP_CTRL_CCM_GET_TAG).")
        }

        return buffer
    }

    func setTag<Data>(_ tag: Data)
        where Data: DataProtocol
    {
        var buffer = tag.copyBytes()

        /// Require that the tag length is full-sized. Although it is possible to use the leftmost bytes of a tag,
        /// shorter tags pose both a buffer size risk as well as an attack risk.
        guard buffer.count == AEAD_MAX_TAG_LENGTH else {
            fatalError("Tag length too short: \(buffer.count) != \(AEAD_MAX_TAG_LENGTH) (AEAD_MAX_TAG_LENGTH).")
        }

        guard EVP_CIPHER_CTX_ctrl(
            self.context,
            EVP_CTRL_GCM_SET_TAG,
            AEAD_MAX_TAG_LENGTH,
            &buffer
        ) == 1 else {
            fatalError("Failed setting tag (EVP_CTRL_GCM_SET_TAG).")
        }
    }

    deinit {
        EVP_CIPHER_CTX_free(self.context)
    }
}

/// Max Tag Length. Used for defining the size of input and output tags.
///     Redefined from OpenSSL's EVP_AEAD_MAX_TAG_LENGTH, which seems to be improperly defined on some platforms.
///     You can find the original #define here: https://github.com/libressl/libressl/blob/master/src/crypto/evp/evp.h#L1237-L1239
private let AEAD_MAX_TAG_LENGTH: Int32 = 16
