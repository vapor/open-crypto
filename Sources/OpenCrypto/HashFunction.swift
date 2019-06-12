public protocol HashFunction {
    associatedtype Digest : OpenCrypto.Digest
    
    static func hash(bufferPointer: UnsafeRawBufferPointer) -> Self.Digest
    
    init()
    
    mutating func update(bufferPointer: UnsafeRawBufferPointer)
    
    func finalize() -> Self.Digest
}

extension HashFunction {
    /// Computes a digest of the data.
    ///
    /// - Parameter data: The data to be hashed
    /// - Returns: The computed digest
    @inlinable public static func hash<D>(data: D) -> Self.Digest where D : DataProtocol {
        fatalError()
    }
    
    /// Updates the hasher with the data.
    ///
    /// - Parameter data: The data to update the hash
    @inlinable public mutating func update<D>(data: D) where D : DataProtocol {
        fatalError()
    }
}
