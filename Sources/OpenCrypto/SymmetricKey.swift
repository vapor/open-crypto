public struct SymmetricKey : ContiguousBytes, Equatable {
    let bytes: [UInt8]

    public var bitCount: Int {
        return self.bytes.count * 8
    }

    init(bytes: [UInt8]) {
        self.bytes = bytes
    }

    public init(size: SymmetricKeySize) {
        self.bytes = [UInt8].random(count: size.bitCount / 8)
    }

    public init<D>(data: D) where D : ContiguousBytes {
        let bytes = data.withUnsafeBytes { buffer in
            return [UInt8](buffer)
        }
        self.init(bytes: bytes)
    }

    public func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
        return try self.bytes.withUnsafeBytes(body)
    }
}

public struct SymmetricKeySize {
    public static var bits128: SymmetricKeySize {
        return .init(bitCount: 128)
    }
    public static var bits192: SymmetricKeySize {
        return .init(bitCount: 192)
    }
    public static var bits256: SymmetricKeySize {
        return .init(bitCount: 256)
    }

    public let bitCount: Int

    public init(bitCount: Int) {
        self.bitCount = bitCount
    }
}
