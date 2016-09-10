import Essentials
import Core
import CLibreSSL

public final class Hash {
    public let method: Method
    public let stream: ByteStream

    /**
        Creates a hasher from a
        stream of bytes.
     
        The most basic byte stream is
        just an array of bytes called BasicByteStream.
    */
    public init(_ method: Method, _ stream: ByteStream) {
        self.method = method
        self.stream = stream
    }

    public enum Error: Swift.Error {
        case initialize
        case updating
        case finalize
    }

    /**
        Creates the message digest
        as an array of bytes.
    */
    public func hash() throws -> Bytes {
        switch method {
        case .sha1:
            return try hashLibre(
                context: SHA_CTX(),
                initialize: SHA1_Init,
                update: SHA1_Update,
                final: SHA1_Final,
                length: SHA_DIGEST_LENGTH
            )
        case .sha224:
            return try hashLibre(
                context: SHA256_CTX(),
                initialize: SHA224_Init,
                update: SHA224_Update,
                final: SHA224_Final,
                length: SHA224_DIGEST_LENGTH
            )
        case .sha256:
            return try hashLibre(
                context: SHA256_CTX(),
                initialize: SHA256_Init,
                update: SHA256_Update,
                final: SHA256_Final,
                length: SHA256_DIGEST_LENGTH
            )
        case .sha384:
            return try hashLibre(
                context: SHA512_CTX(),
                initialize: SHA384_Init,
                update: SHA384_Update,
                final: SHA384_Final,
                length: SHA384_DIGEST_LENGTH
            )
        case .sha512:
            return try hashLibre(
                context: SHA512_CTX(),
                initialize: SHA512_Init,
                update: SHA512_Update,
                final: SHA512_Final,
                length: SHA512_DIGEST_LENGTH
            )
        case .md5:
            return try hashLibre(
                context: MD5_CTX(),
                initialize: MD5_Init,
                update: MD5_Update,
                final: MD5_Final,
                length: MD5_DIGEST_LENGTH
            )
        case .md4:
            return try hashLibre(
                context: MD4_CTX(),
                initialize: MD4_Init,
                update: MD4_Update,
                final: MD4_Final,
                length: MD4_DIGEST_LENGTH
            )
        case .ripemd160:
            return try hashLibre(
                context: RIPEMD160_CTX(),
                initialize: RIPEMD160_Init,
                update: RIPEMD160_Update,
                final: RIPEMD160_Final,
                length: RIPEMD160_DIGEST_LENGTH
            )
        }
    }

    private func hashLibre<T>(
        context: T,
        initialize: (UnsafeMutablePointer<T>) -> Int32,
        update: (UnsafeMutablePointer<T>, UnsafeRawPointer, Int) -> Int32,
        final: (UnsafeMutablePointer<UInt8>, UnsafeMutablePointer<T>) -> Int32,
        length: Int32
    ) throws -> Bytes{
        var context = context
        guard initialize(&context) == 1 else {
            throw Error.initialize
        }

        while !stream.closed {
            let bytes = try stream.next()
            guard update(&context, bytes, bytes.count) == 1 else {
                throw Error.updating
            }
        }

        var digest = Bytes(repeating: 0, count: Int(length))
        guard final(&digest, &context) == 1 else {
            throw Error.finalize
        }
        
        return digest
    }
}

extension Hash {

    /**
        Create the hasher from an array
        of bytes. This will internally
        create a BasicByteStream.
    */
    public convenience init(_ method: Method, _ bytes: Bytes) {
        let inputStream = BasicByteStream(bytes)
        self.init(method, inputStream)
    }

    /**
        Create the hasher from something
        representable as bytes. This will internally
        create a BasicByteStream.
    */
    public convenience init<B: BytesRepresentable>(_ method: Method, _ bytes: B) throws {
        self.init(method, try bytes.makeBytes())
    }

    /**
        Hash an array of bytes without
        initializing a hasher.
    */
    public static func make(_ method: Method, _ bytes: Bytes) throws -> Bytes {
        let hasher = Hash(method, bytes)
        return try hasher.hash()
    }

    /**
        Hash an array of something representable
        as bytes without initializing a hasher.
    */
    public static func make<B: BytesRepresentable>(_ method: Method, _ bytes: B) throws -> Bytes {
        return try make(method, try bytes.makeBytes())
    }
}
