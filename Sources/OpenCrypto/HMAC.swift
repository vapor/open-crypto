import COpenCrypto

public struct HMAC<H> where H : HashFunction {
    static var algorithm: OpaquePointer {
        guard let opensslDigest = H.Digest.self as? AnyOpenSSLDigest.Type else {
            fatalError("\(H.self) is not an OpenSSL hash function")
        }
        return opensslDigest.algorithm
    }

    public static func authenticationCode<D>(
        for data: D,
        using key: SymmetricKey
    ) -> HashedAuthenticationCode<H>
        where D : DataProtocol
    {
        var hmac = self.init(key: key)
        hmac.update(data: data)
        return hmac.finalize()
    }

    public static func isValidAuthenticationCode(
        _ mac: HashedAuthenticationCode<H>,
        authenticating bufferPointer: UnsafeRawBufferPointer,
        using key: SymmetricKey
    ) -> Bool {
        return self.authenticationCode(for: bufferPointer, using: key) == mac
    }

    public static func isValidAuthenticationCode<D>(
        _ authenticationCode: HashedAuthenticationCode<H>,
        authenticating authenticatedData: D,
        using key: SymmetricKey
    ) -> Bool
        where D : DataProtocol
    {
        return self.authenticationCode(for: authenticatedData, using: key) == authenticationCode
    }

    public static func isValidAuthenticationCode<D>(
        _ authenticationCode: ContiguousBytes,
        authenticating authenticatedData: D,
        using key: SymmetricKey
    ) -> Bool
        where D : DataProtocol
    {
        return authenticationCode.withUnsafeBytes { buffer in
            return self.authenticationCode(for: authenticatedData, using: key).bytes == [UInt8](buffer)
        }
    }

    let key: SymmetricKey
    let context: OpaquePointer

    public init(key: SymmetricKey) {
        self.key = key
        self.context = HMAC_CTX_new()
        self.initialize()
    }

    public mutating func update<D>(data: D)
        where D : DataProtocol
    {
        if let digest = data.withContiguousStorageIfAvailable({ buffer in
            return self.update(bufferPointer: .init(buffer))
        }) {
            return digest
        } else {
            var buffer = UnsafeMutableBufferPointer<UInt8>.allocate(capacity: data.count)
            data.copyBytes(to: buffer)
            defer { buffer.deallocate() }
            return self.update(bufferPointer: .init(buffer))
        }
    }

    private mutating func update(bufferPointer: UnsafeRawBufferPointer) {
        guard bufferPointer.withUnsafeBytes({
            return HMAC_Update(self.context, $0.baseAddress?.assumingMemoryBound(to: UInt8.self), $0.count)
        }) == 1 else {
            fatalError("Failed updating HMAC digest")
        }
    }

    public func finalize() -> HashedAuthenticationCode<H> {
        var hash = [UInt8](repeating: 0, count: Int(EVP_MAX_MD_SIZE))
        var count: UInt32 = 0

        guard hash.withUnsafeMutableBytes({
            return HMAC_Final(self.context, $0.baseAddress?.assumingMemoryBound(to: UInt8.self), &count)
        }) == 1 else {
            fatalError("Failed finalizing HMAC digest")
        }

        self.free()
        return .init(bytes: .init(hash[0..<Int(count)]))
    }

    private func initialize() {
        guard self.key.withUnsafeBytes({
            return HMAC_Init_ex(self.context, $0.baseAddress?.assumingMemoryBound(to: UInt8.self), Int32($0.count), Self.algorithm, nil)
        }) == 1 else {
            fatalError("Failed initializing HMAC context")
        }
    }

    private func free() {
        HMAC_CTX_free(self.context)
    }
}
