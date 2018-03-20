import Foundation

public protocol DataRepresentable {
    func makeData() throws -> Data
}

extension String: DataRepresentable {
    public func makeData() throws -> Data {
        return Data(utf8)
    }
}

extension Array: DataRepresentable where Element == UInt8 {
    public func makeData() throws -> Data {
        return Data(bytes: self)
    }
}

extension Data: DataRepresentable {
    public func makeData() throws -> Data {
        return self
    }
}
