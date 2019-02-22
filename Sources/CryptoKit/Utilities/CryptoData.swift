import Foundation

public enum CryptoData {
    case data(Data)
    case string(String)
    case staticString(StaticString)
    case bytes(Array<UInt8>)
    case bytesSlice(ArraySlice<UInt8>)
    
    public var count: Int {
        switch self {
        case .data(let data): return data.count
        case .string(let string): return string.utf8.count
        case .staticString(let staticString): return staticString.utf8CodeUnitCount
        case .bytes(let bytes): return bytes.count
        case .bytesSlice(let bytesSlice): return bytesSlice.count
        }
    }
    
    public func string() -> String {
        switch self {
        case .data(let data): return String(decoding: data, as: Unicode.UTF8.self)
        case .string(let string): return string
        case .bytes(let bytes): return String(decoding: bytes, as: Unicode.UTF8.self)
        case .bytesSlice(let bytes): return String(decoding: bytes, as: Unicode.UTF8.self)
        case .staticString(let string): return string.description
        }
    }
    
    public func bytes() -> [UInt8] {
        switch self {
        case .data(let data): return .init(data)
        case .string(let string): return .init(string.utf8)
        case .bytes(let bytes): return bytes
        case .bytesSlice(let bytes): return .init(bytes)
        case .staticString(let string): return .init(UnsafeBufferPointer(start: string.utf8Start, count: string.utf8CodeUnitCount))
        }
    }
    
    public func hexEncodedString() -> String {
        switch self {
        case .data(let data): return data.hexEncodedString()
        case .string(let string): return string.utf8.hexEncodedString()
        case .bytes(let bytes): return bytes.hexEncodedString()
        case .bytesSlice(let bytes): return bytes.hexEncodedString()
        case .staticString(let string): return string.description.utf8.hexEncodedString()
        }
    }
    
    public func base32EncodedString() -> String {
        switch self {
        case .data(let data): return data.base32EncodedString()
        case .string(let string): return Data(string.utf8).base32EncodedString()
        case .bytes(let bytes): return Data(bytes).base32EncodedString()
        case .bytesSlice(let bytes): return Data(bytes).base32EncodedString()
        case .staticString(let string): return Data(string.description.utf8).base32EncodedString()
        }
    }
}

extension CryptoData: CustomStringConvertible {
    /// `CustomStringConvertible` conformance.
    public var description: String {
        return self.string()
    }
}

extension CryptoData: Equatable {
    /// `Equatable` conformance.
    public static func == (lhs: CryptoData, rhs: CryptoData) -> Bool {
        switch (lhs, rhs) {
        case (.data(let a), .data(let b)): return a == b
        case (.string(let a), .string(let b)): return a == b
        case (.bytes(let a), .bytes(let b)): return a == b
        case (.bytesSlice(let a), .bytesSlice(let b)): return a == b
        default: return lhs.bytes() == rhs.bytes()
        }
    }
}

extension CryptoData: Codable {
    public init(from decoder: Decoder) throws {
        let single = try decoder.singleValueContainer()
        self = try .string(single.decode(String.self))
    }
    
    public func encode(to encoder: Encoder) throws {
        var single = encoder.singleValueContainer()
        try single.encode(self.string())
    }
}

extension CryptoData: ExpressibleByStringLiteral {
    public init(stringLiteral value: StaticString) {
        self = .staticString(value)
    }
}

extension Optional where Wrapped == CryptoData {
    func withUnsafeBytes<R>(_ closure: (UnsafeRawBufferPointer?) throws -> R) rethrows -> R {
        switch self {
        case .none:
            return try closure(nil)
        case .some(let some):
            return try some.withUnsafeBytes(closure)
        }
    }
    
}

extension CryptoData {
    func withUnsafeBytes<R>(_ closure: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
        switch self {
        case .data(let data):
            return try data.withUnsafeBytes(closure)
        case .string(let string):
            guard let r = try string.withContiguousStorageIfAvailable ({ storage in
                try closure(UnsafeRawBufferPointer(storage))
            }) else {
                print("[CryptoKit] String slow path hit.")
                return try Array(string.utf8).withUnsafeBytes(closure)
            }
            return r
        case .bytes(let bytes):
            return try bytes.withUnsafeBytes(closure)
        case .bytesSlice(let bytes):
            return try bytes.withUnsafeBytes(closure)
        case .staticString(let string):
            let buffer = UnsafeRawBufferPointer(start: string.utf8Start, count: string.utf8CodeUnitCount)
            return try closure(buffer)
        }
    }
}
