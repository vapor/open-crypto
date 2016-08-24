import Core

public protocol Hash {
    static var blockSize: Int { get }

    init(_ stream: ByteStream)
    func hash() throws -> Bytes
}

extension Hash {
    public init(_ bytes: Bytes) {
        let inputStream = BasicByteStream(bytes)
        self.init(inputStream)
    }

    public static func hash(_ bytes: Bytes) throws -> Bytes {
        let hasher = Self(bytes)
        return try hasher.hash()
    }
}
