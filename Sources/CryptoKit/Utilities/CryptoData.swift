import Foundation

public enum CryptoData {
    case data(Data)
    case string(String)
    case staticString(StaticString)
    case array(Array<UInt8>)
    case arraySlice(ArraySlice<UInt8>)
    
    public func string() -> String {
        switch self {
        case .data(let data): return String(decoding: data, as: Unicode.UTF8.self)
        case .string(let string): return string
        case .array(let bytes): return String(decoding: bytes, as: Unicode.UTF8.self)
        case .arraySlice(let bytes): return String(decoding: bytes, as: Unicode.UTF8.self)
        case .staticString(let string): return string.description
        }
    }
    
    public func hexEncodedString() -> String {
        switch self {
        case .data(let data): return data.hexEncodedString()
        case .string(let string): return string.utf8.hexEncodedString()
        case .array(let bytes): return bytes.hexEncodedString()
        case .arraySlice(let bytes): return bytes.hexEncodedString()
        case .staticString(let string): return string.description.utf8.hexEncodedString()
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
        case .array(let bytes):
            return try bytes.withUnsafeBytes(closure)
        case .arraySlice(let bytes):
            return try bytes.withUnsafeBytes(closure)
        case .staticString(let string):
            let buffer = UnsafeRawBufferPointer(start: string.utf8Start, count: string.utf8CodeUnitCount)
            return try closure(buffer)
        }
    }
}
