import COpenCrypto

public enum OpenSSL {
    public static var version: Int {
        return numericCast(c_open_crypto_openssl_version_number())
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
