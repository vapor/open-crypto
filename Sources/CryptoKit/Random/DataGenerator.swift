import Foundation

/// Capable of generating random `Data`.
public protocol DataGenerator {
    /// Generate `count` bytes of data.
    func generateData(count: Int) throws -> Data
}

extension Data {
    internal func cast<T>(to: T.Type = T.self) -> T {
        return withUnsafeBytes { (p: UnsafeRawBufferPointer) in p.baseAddress!.assumingMemoryBound(to: T.self).pointee }
    }
}

extension DataGenerator {
    /// Generates a random type `T`.
    public func generate<T>(_ type: T.Type = T.self) throws -> T {
        return try self.generateData(count: MemoryLayout<T>.size)
            .cast(to: T.self)
    }
}
