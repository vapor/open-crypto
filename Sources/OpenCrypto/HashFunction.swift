public protocol HashFunction {
    associatedtype Digest : OpenCrypto.Digest
    
    static func hash(bufferPointer: UnsafeRawBufferPointer) -> Self.Digest
    
    init()
    
    mutating func update(bufferPointer: UnsafeRawBufferPointer)
    
    func finalize() -> Self.Digest
}

extension HashFunction {
    public static func hash<D>(data: D) -> Self.Digest where D : DataProtocol {
        if let digest = data.withContiguousStorageIfAvailable({ buffer in
            return self.hash(bufferPointer: .init(buffer))
        }) {
            return digest
        } else {
            var buffer = UnsafeMutableBufferPointer<UInt8>.allocate(capacity: data.count)
            data.copyBytes(to: buffer)
            defer { buffer.deallocate() }
            return self.hash(bufferPointer: .init(buffer))
        }
    }

    public mutating func update<D>(data: D) where D : DataProtocol {
        if let digest = data.withContiguousStorageIfAvailable({ buffer in
            return self.update(bufferPointer: .init(buffer))
        }) {
            return digest
        } else {
            return data.copyBytes().withUnsafeBufferPointer({ buffer in self.update(bufferPointer: .init(buffer))
            })
        }
    }
}
