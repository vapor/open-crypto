import Core

public protocol Hash {
    static var blockSize: Int { get }

    init(_ stream: ByteStream)
    func hash() throws -> ByteStream
}

extension Hash {
    public init(_ bytes: Bytes) {
        let inputStream = BasicByteStream(bytes)
        self.init(inputStream)
    }

    public func hash() throws -> Bytes {
        let outputStream: ByteStream = try self.hash()

        var output: Bytes = []
        while !outputStream.closed {
            let next = try outputStream.next(Self.blockSize)
            output += next
        }

        return output
    }

    public static func hash(_ bytes: Bytes) throws -> Bytes {
        let hasher = Self(bytes)
        return try hasher.hash()
    }
}
