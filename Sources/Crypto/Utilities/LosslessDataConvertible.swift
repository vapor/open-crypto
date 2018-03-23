import Foundation

public protocol LosslessDataConvertible {
    func convertToData() throws -> Data
    static func convertFromData(_ data: Data) -> Self
}

extension String: LosslessDataConvertible {
    public func convertToData() throws -> Data {
        return Data(utf8)
    }

    public static func convertFromData(_ data: Data) -> String {
        return String(data: data, encoding: .ascii) ?? ""
    }
}

extension Array: LosslessDataConvertible where Element == UInt8 {
    public func convertToData() throws -> Data {
        return Data(bytes: self)
    }

    public static func convertFromData(_ data: Data) -> Array<UInt8> {
        return .init(data)
    }
}

extension Data: LosslessDataConvertible {
    public func convertToData() throws -> Data {
        return self
    }

    public static func convertFromData(_ data: Data) -> Data {
        return data
    }
}
