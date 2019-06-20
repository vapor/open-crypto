import COpenCrypto

enum CipherMode: Int32 {
    case encrypt = 1
    case decrypt = 0
}

public protocol CipherFunction {
    associatedtype Nonce
    associatedtype SealedBox

    static func seal<Plaintext>(
        _ message: Plaintext,
        using key: SymmetricKey,
        nonce: Nonce?
    ) throws -> SealedBox
        where Plaintext : DataProtocol

    static func open(
        _ sealedBox: SealedBox,
        using key: SymmetricKey
    ) throws -> [UInt8]
}

extension CipherFunction {
    public static func seal<Plaintext>(
        _ message: Plaintext,
        using key: SymmetricKey
    ) throws -> SealedBox
        where Plaintext : DataProtocol
    {
        return try self.seal(message, using: key, nonce: nil)
    }
}

protocol OpenSSLCipherNonce {
    init()
    var bytes: [UInt8] { get }
}

protocol OpenSSLCipherSealedBox {
    associatedtype Nonce: OpenSSLCipherNonce
    var tag: [UInt8] { get }
    var nonce: Nonce { get }
    var ciphertext: [UInt8] { get }
    init(nonce: Nonce, ciphertext: [UInt8], tag: [UInt8])
}

protocol OpenSSLCipherFunction: CipherFunction
    where SealedBox: OpenSSLCipherSealedBox, Nonce == SealedBox.Nonce
{
    static func algorithm(for key: SymmetricKey) throws -> OpaquePointer
}

extension OpenSSLCipherFunction {
    public static func seal<Plaintext>(
        _ message: Plaintext,
        using key: SymmetricKey,
        nonce: Nonce?
    ) throws -> SealedBox
        where Plaintext : DataProtocol
    {
        let algorithm = try self.algorithm(for: key)
        let context = EVP_CIPHER_CTX_new()!
        defer { EVP_CIPHER_CTX_free(context) }
        let nonce = nonce ?? Nonce()

        var buffer = [UInt8]()
        try self.reset(context: convert(context), algorithm: algorithm, key: key, iv: nonce.bytes, mode: .encrypt)
        try self.update(context: convert(context), algorithm: algorithm, data: message, into: &buffer)
        try self.finish(context: convert(context), algorithm: algorithm, into: &buffer)

        return try SealedBox(nonce: nonce, ciphertext: buffer, tag: self.getTag(context: convert(context)))
    }

    public static func open(
        _ sealedBox: SealedBox,
        using key: SymmetricKey
    ) throws -> [UInt8] {
        let algorithm = try self.algorithm(for: key)
        let context = EVP_CIPHER_CTX_new()!
        defer { EVP_CIPHER_CTX_free(context) }

        var buffer = [UInt8]()
        try self.reset(context: convert(context), algorithm: algorithm, key: key, iv: sealedBox.nonce.bytes, mode: .decrypt)
        try self.setTag(context: convert(context), sealedBox.tag)
        try self.update(context: convert(context), algorithm: algorithm, data: sealedBox.ciphertext, into: &buffer)
        try self.finish(context: convert(context), algorithm: algorithm, into: &buffer)
        return buffer
    }

    private static func reset<IV>(
        context: OpaquePointer,
        algorithm: OpaquePointer,
        key: SymmetricKey,
        iv: IV,
        mode: CipherMode
    ) throws
        where IV: DataProtocol
    {
        guard key.bitCount == numericCast(EVP_CIPHER_key_length(convert(algorithm))) * 8 else {
            throw CryptoKitError.incorrectKeySize
        }
        guard iv.count == numericCast(EVP_CIPHER_iv_length(convert(algorithm))) else {
            throw CryptoKitError.incorrectParameterSize
        }

        guard EVP_CipherInit_ex(
            convert(context),
            convert(algorithm),
            nil,
            key.bytes,
            iv.copyBytes(),
            mode.rawValue
        ) == 1 else {
            throw CryptoKitError.underlyingCoreCryptoError(error: 0)
        }
    }

    private static func update<Data>(
        context: OpaquePointer,
        algorithm: OpaquePointer,
        data: Data,
        into buffer: inout [UInt8]
    ) throws
        where Data: DataProtocol
    {
        let data = data.copyBytes()
        var chunk = [UInt8](repeating: 0, count: data.count + numericCast(EVP_CIPHER_block_size(convert(algorithm))) - 1)
        var chunkLength: Int32 = 0

        guard EVP_CipherUpdate(
            convert(context),
            &chunk,
            &chunkLength,
            data,
            numericCast(data.count)
        ) == 1 else {
            throw CryptoKitError.underlyingCoreCryptoError(error: 0)
        }
        buffer += chunk.prefix(upTo: Int(chunkLength))
    }

    private static func finish(
        context: OpaquePointer,
        algorithm: OpaquePointer,
        into buffer: inout [UInt8]
    ) throws {
        var chunk = [UInt8](repeating: 0, count: numericCast(EVP_CIPHER_block_size(convert(algorithm))))
        var chunkLength: Int32 = 0

        guard EVP_CipherFinal_ex(
            convert(context),
            &chunk,
            &chunkLength
        ) == 1 else {
            throw CryptoKitError.underlyingCoreCryptoError(error: 0)
        }
        buffer += chunk.prefix(upTo: Int(chunkLength))
    }

    private static func getTag(context: OpaquePointer) throws -> [UInt8] {
        var buffer = [UInt8](repeating: 0, count: Int(AEAD_MAX_TAG_LENGTH))

        guard EVP_CIPHER_CTX_ctrl(
            convert(context),
            EVP_CTRL_GCM_GET_TAG,
            AEAD_MAX_TAG_LENGTH,
            &buffer
        ) == 1 else {
            throw CryptoKitError.underlyingCoreCryptoError(error: 0)
        }

        return buffer
    }

    private static func setTag<Data>(context: OpaquePointer, _ tag: Data) throws
        where Data: DataProtocol
    {
        var buffer = tag.copyBytes()
        guard buffer.count == AEAD_MAX_TAG_LENGTH else {
            throw CryptoKitError.underlyingCoreCryptoError(error: 0)
        }

        guard EVP_CIPHER_CTX_ctrl(
            convert(context),
            EVP_CTRL_GCM_SET_TAG,
            AEAD_MAX_TAG_LENGTH,
            &buffer
        ) == 1 else {
            fatalError("Failed setting tag (EVP_CTRL_GCM_SET_TAG).")
        }
    }
}

private let AEAD_MAX_TAG_LENGTH: Int32 = 16
