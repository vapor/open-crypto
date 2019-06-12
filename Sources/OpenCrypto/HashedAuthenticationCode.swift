public struct HashedAuthenticationCode<H> : MessageAuthenticationCode where H : HashFunction {
    public typealias Element = UInt8

    public static var byteCount: Int {
        guard let opensslDigest = H.Digest.self as? AnyOpenSSLDigest.Type else {
            fatalError("\(H.self) is not an OpenSSL hash function")
        }
        return opensslDigest.byteCount
    }

    let bytes: [UInt8]

    init(bytes: [UInt8]) {
        self.bytes = bytes
    }

    public var description: String {
        return self.bytes.hexEncodedString()
    }

    public func makeIterator() -> Array<UInt8>.Iterator {
        return self.bytes.makeIterator()
    }

    public func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
        return try self.bytes.withUnsafeBytes(body)
    }
}
