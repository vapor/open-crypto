import COpenCrypto

protocol AnyOpenSSLDigest {
    static var algorithm: OpaquePointer { get }
    static var byteCount: Int { get }
}

protocol OpenSSLDigest: Digest, AnyOpenSSLDigest {
    var bytes: [UInt8] { get }
    init(bytes: [UInt8])
}

extension OpenSSLDigest {
    public static var byteCount: Int {
        return numericCast(EVP_MD_size(convert(self.algorithm)))
    }

    public func makeIterator() -> Array<UInt8>.Iterator {
        return self.bytes.makeIterator()
    }

    public init?(bufferPointer: UnsafeRawBufferPointer) {
        self.init(bytes: [UInt8](bufferPointer))
    }

    public func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
        return try self.bytes.withUnsafeBytes(body)
    }

    public var description: String {
        return self.bytes.hexEncodedString()
    }
}

protocol OpenSSLHashFunction: HashFunction
    where Digest: OpenSSLDigest
{
    init(context: OpaquePointer)
    var context: OpaquePointer { get }
}

extension OpenSSLHashFunction {
    public static func hash(bufferPointer: UnsafeRawBufferPointer) -> Digest {
        let digest = self.init()
        digest.update(bufferPointer: bufferPointer)
        return digest.finalize()
    }

    public init() {
        self.init(context: convert(EVP_MD_CTX_new()))
        self.initialize()
    }

    public func update(bufferPointer: UnsafeRawBufferPointer) {
        guard bufferPointer.withUnsafeBytes({
            EVP_DigestUpdate(convert(self.context), $0.baseAddress, $0.count)
        }) == 1 else {
            fatalError("Failed updating digest")
        }
    }

    public func finalize() -> Digest {
        var hash: [UInt8] = .init(repeating: 0, count: Int(EVP_MAX_MD_SIZE))
        var count: UInt32 = 0

        guard hash.withUnsafeMutableBytes({
            EVP_DigestFinal_ex(convert(self.context), $0.baseAddress?.assumingMemoryBound(to: UInt8.self), &count)
        }) == 1 else {
            fatalError("Failed finalizing digest")
        }
        self.free()
        return .init(bytes: .init(hash[0..<Int(count)]))
    }

    private func initialize() {
        guard EVP_DigestInit_ex(convert(self.context), convert(Digest.algorithm), nil) == 1 else {
            fatalError("Failed initializing digest context")
        }
    }

    private func free() {
        EVP_MD_CTX_free(convert(self.context))
    }
}
