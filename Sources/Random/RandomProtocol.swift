import Foundation

/// Capable of generating random `Data`.
public protocol DataGenerator {
    /// Generate `count` bytes of data.
    func generateData(count: Int) throws -> Data
}

extension Data {
    /// Converts the data to an unsafe raw pointer.
    internal var rawPointer: UnsafeRawPointer {
        let bytes: UnsafePointer<UInt8> = withUnsafeBytes { $0 }
        return UnsafeRawPointer(bytes)
    }

    internal func cast<T>(to: T.Type = T.self) -> T {
        return rawPointer
            .assumingMemoryBound(to: T.self)
            .pointee
    }
}

extension DataGenerator {
    /// Generates a random type `T`.
    public func generate<T>(_ type: T.Type = T.self) throws -> T {
        return try generateData(count: MemoryLayout<T>.size)
            .cast(to: T.self)
    }
}
