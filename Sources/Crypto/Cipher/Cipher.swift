import CLibreSSL

public final class Cipher {
    public let method: Method
    public let key: Bytes
    public let iv: Bytes?

    /// Creates a cipher for encrypting and decrypting
    /// byte streams using the supplied key and optionally
    /// initialization vector.
    ///
    /// - method: The cipher method to use
    /// - key: The crypto key
    /// - iv: Optional initialization vector, defaults to the key if `useIV` is true.
    ///
    /// Note: Some cipher methods may require an intialization vector
    /// to work properly.
    public init(
        _ method: Method,
        key: Bytes,
        iv: Bytes? = nil
    ) throws {
        let keyLen = Int(EVP_CIPHER_key_length(method.evp))
        guard key.count == keyLen else {
            throw Error.invalidKeyLength(expected: keyLen)
        }

        self.method = method
        self.key = key

        if let iv = iv {
            let ivLen = Int(EVP_CIPHER_iv_length(method.evp))
            guard ivLen == iv.count else {
                throw Error.invalidInitializationVectorLength(expected: ivLen)
            }
            self.iv = iv
        } else {
            self.iv = nil
        }
    }

    public enum Error: Swift.Error {
        case initialize
        case update
        case finalize
        case invalidKeyLength(expected: Int)
        case invalidInitializationVectorLength(expected: Int)
    }

    public func encrypt(_ stream: ByteStream) throws -> Bytes {
        return try libreCipher(
            stream: stream,
            initialize: { EVP_EncryptInit($0, $1, $2, $3) },
            update: EVP_EncryptUpdate,
            final: EVP_EncryptFinal
        )
    }

    public func decrypt(_ stream: ByteStream) throws -> Bytes {
        return try libreCipher(
            stream: stream,
            initialize: { EVP_DecryptInit($0, $1, $2, $3) },
            update: EVP_DecryptUpdate,
            final: EVP_DecryptFinal
        )
    }

    private func libreCipher(
        stream: ByteStream,
        initialize: (
            UnsafeMutablePointer<EVP_CIPHER_CTX>,
            UnsafePointer<EVP_CIPHER>,
            UnsafePointer<UInt8>,
            UnsafePointer<UInt8>?
        ) -> Int32,
        update: (
            UnsafeMutablePointer<EVP_CIPHER_CTX>,
            UnsafeMutablePointer<UInt8>,
            UnsafeMutablePointer<Int32>,
            UnsafePointer<UInt8>,
            Int32
        ) -> Int32,
        final: (
            UnsafeMutablePointer<EVP_CIPHER_CTX>,
            UnsafeMutablePointer<UInt8>,
            UnsafeMutablePointer<Int32>
        ) -> Int32
    ) throws -> Bytes {
        var ctx = EVP_CIPHER_CTX()

        guard initialize(&ctx, method.evp, key, iv) == 1 else {
            throw Error.initialize
        }

        var parsed: Bytes = []

        while !stream.closed {
            var newLength: Int32 = 0
            let bytes = try stream.next()


            let bufferLength = bytes.count + Int(EVP_MAX_BLOCK_LENGTH)
            let buffer = UnsafeMutablePointer<Byte>.allocate(capacity: bufferLength)
            defer {
                buffer.deinitialize()
                buffer.deallocate(capacity: bufferLength)
            }

            guard update(&ctx, buffer, &newLength, bytes, Int32(bytes.count)) == 1 else {
                throw Error.update
            }

            let bufferPointer = UnsafeMutableBufferPointer(start: buffer, count: Int(newLength))
            let newParsed = Array(bufferPointer)
            parsed += newParsed

        }

        let bufferLength = Int(1024 + EVP_MAX_BLOCK_LENGTH)
        let buffer = UnsafeMutablePointer<Byte>.allocate(capacity: bufferLength)
        defer {
            buffer.deinitialize()
            buffer.deallocate(capacity: bufferLength)
        }

        var endLength: Int32 = 0
        guard final(&ctx, buffer, &endLength) == 1 else {
            throw Error.finalize
        }

        let bufferPointer = UnsafeMutableBufferPointer(start: buffer, count: Int(endLength))
        let end = Array(bufferPointer)
        parsed += end
        
        return parsed
    }
}

extension Cipher {
    public func encrypt(_ bytes: Bytes) throws -> Bytes {
        let stream = BasicByteStream(bytes)
        return try encrypt(stream)
    }

    public func decrypt(_ bytes: Bytes) throws -> Bytes {
        let stream = BasicByteStream(bytes)
        return try decrypt(stream)
    }
}

