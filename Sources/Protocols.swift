import Core

public protocol Hash: class {
    static var blockSize: Int { get }
    
    static func hash(_ message: BytesSlice) -> Bytes
}

extension Hash {
    public static func hash(_ message: Bytes) -> Bytes {
        return hash(message[message.startIndex..<message.endIndex])
    }
}

public protocol StreamingHash: Hash {
    init()
    
    func append(bytes: Bytes)
    func complete() -> Bytes
}
