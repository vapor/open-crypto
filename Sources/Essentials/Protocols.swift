import Core

public protocol Hash: class {
    static var blockSize: Int { get }
    
    static func hash(_ message: Bytes) -> Bytes
}

public protocol StreamingHash: Hash {
    init()
    
    func append(bytes: Bytes)
    func complete() -> Bytes
}
