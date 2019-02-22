/// Capable of generating random `Data`.
public protocol DataGenerator {
    /// Generate `count` bytes of data.
    func generateData(count: Int) throws -> [UInt8]
}

extension DataGenerator {
    /// Generates a random type `T`.
    public func generate<T>(_ type: T.Type = T.self) throws -> T
        where T: FixedWidthInteger
    {
        return try self.generateData(count: MemoryLayout<T>.size)
            .withUnsafeBytes { $0.baseAddress!.assumingMemoryBound(to: T.self).pointee }
    }
}
