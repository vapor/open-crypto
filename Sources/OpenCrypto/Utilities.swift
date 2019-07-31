import COpenCrypto

public struct OpenSSLVersion: Comparable, Equatable, Hashable {
    public static func < (lhs: OpenSSLVersion, rhs: OpenSSLVersion) -> Bool {
        return lhs.value < rhs.value
    }

    let value: Int32

    public static var v1_1: OpenSSLVersion {
        return .init(value: 0x10_10_00_00)
    }

    public static var v1_0: OpenSSLVersion {
        return .init(value: 0x10_00_00_00)
    }

    public static var current: OpenSSLVersion {
        return .init(value: c_open_crypto_openssl_version_number())
    }
}

extension DataProtocol {
    func copyBytes() -> [UInt8] {
        var buffer = UnsafeMutableBufferPointer<UInt8>.allocate(capacity: self.count)
        self.copyBytes(to: buffer)
        defer { buffer.deallocate() }
        return .init(buffer)
    }
}

extension Array where Element: FixedWidthInteger {
    static func random(count: Int) -> [Element] {
        var array = self.init()
        for _ in 0..<count {
            array.append(.random(in: Element.min..<Element.max))
        }
        return array
    }
}

// pointer hacks

func convert(_ pointer: OpaquePointer) -> OpaquePointer {
    return pointer
}

func convert<T>(_ pointer: UnsafePointer<T>) -> OpaquePointer {
    return .init(pointer)
}

func convert<T>(_ pointer: UnsafeMutablePointer<T>) -> OpaquePointer {
    return .init(pointer)
}

func convert<T>(_ pointer: OpaquePointer) -> UnsafePointer<T> {
    return .init(pointer)
}

func convert<T>(_ pointer: OpaquePointer) -> UnsafeMutablePointer<T> {
    return .init(pointer)
}
