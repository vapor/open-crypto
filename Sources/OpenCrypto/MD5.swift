extension Insecure {
    public struct MD5: HashFunction {
        public typealias Digest = Insecure.MD5Digest
        
        public static var byteCount: Int {
            fatalError()
        }
        
        public init() {
            
        }
        
        public mutating func update(bufferPointer: UnsafeRawBufferPointer) {
            fatalError()
        }
        
        public func finalize() -> Insecure.MD5.Digest {
            fatalError()
        }
        
        public static func hash(bufferPointer: UnsafeRawBufferPointer) -> Insecure.MD5.Digest {
            fatalError()
        }
    }
    
    public struct MD5Digest: Digest {
        public typealias Element = UInt8
        public typealias Iterator = Array<UInt8>.Iterator
        
        public static var byteCount: Int {
            fatalError()
        }
        
        public init?(bufferPointer: UnsafeRawBufferPointer) {
            
        }
        
        public func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
            fatalError()
        }
            

        public var description: String {
            fatalError()
        }
        
        public func hash(into hasher: inout Hasher) {
            fatalError()
        }
    }
}
