import Core

public class ByteStreamHasher<H: Hash> : InputStream {
    public var hash: [UInt8] {
        return context.hash
    }
    
    public func inputStream(_ input: ByteBuffer) {
        context.update(input)
    }
    
    public required init() {}
    
    public func complete() -> [UInt8] {
        defer {
            context.reset()
        }
        
        return context.hash
    }
    
    public typealias Input = ByteBuffer
    
    public var errorStream: BaseStream.ErrorHandler?
    
    let context = H()
}
