import Core
import Essentials
import CLibreSSL

/// Used to authenticate messages using the `Hash` algorithm
public final class HMAC {
    public let method: Method
    private let stream: ByteStream

    /// Create an HMAC authenticator.
    public init(_ m: Method, _ s: ByteStream) {
        stream = s
        method = m
    }

    public enum Error: Swift.Error {
        case unsupportedMethod
    }

    /// Authenticates a message using the provided `Hash` algorithm
    ///
    /// - parameter message: The message to authenticate
    /// - parameter key: The key to authenticate with
    ///
    /// - returns: The authenticated message
    public func authenticate(key: Bytes) throws -> Bytes {
        var context = HMAC_CTX()
        HMAC_CTX_init(&context)

        HMAC_Init_ex(&context, key, Int32(key.count), method.evp, nil)

        while !stream.closed {
            let bytes = try stream.next()
            HMAC_Update(&context, bytes, bytes.count)
        }


        var digest = Bytes(repeating: 0, count: Int(EVP_MAX_MD_SIZE))
        var length: UInt32 = 0
        HMAC_Final(&context, &digest, &length);
        
        return Array(digest[0..<Int(length)])
    }
}

extension HMAC {
    /// Create the hasher from an array
    /// of bytes. This will internally
    /// create a BasicByteStream.
    public convenience init(_ m: Method, _ bytes: Bytes) {
        let inputStream = BasicByteStream(bytes)
        self.init(m, inputStream)
    }

    /// Create the hasher from something
    /// representable as bytes. This will internally
    /// create a BasicByteStream.
    public convenience init<B: BytesRepresentable>(_ m: Method, _ bytes: B) throws {
        self.init(m, try bytes.makeBytes())
    }

    /// Authenticates a message using something
    /// that can be represented with bytes.
    ///
    /// - see: authenticate(key: Bytes)
    public func authenticate<B: BytesRepresentable>(key: B) throws -> Bytes {
        return try authenticate(key: try key.makeBytes())
    }

    /// Convenience method for easily making
    /// an HMAC digest.
    public static func make(_ method: Method, _ bytes: Bytes, key: Bytes) throws -> Bytes {
        return try HMAC(method, bytes).authenticate(key: key)
    }

    /// Convenience method for easily making
    /// an HMAC digest using Bytes representable.
    public static func make<B1: BytesRepresentable, B2: BytesRepresentable>(_ method: Method, _ bytes: B1, key: B2) throws -> Bytes {
        return try make(method, try bytes.makeBytes(), key: try key.makeBytes())
    }
}
