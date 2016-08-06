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

public protocol ByteStream {
    var closed: Bool { get }
    func next(_ max: Int) throws -> BytesSlice
}

public final class BasicByteStream: ByteStream {
    let bytes: Bytes
    var index: Int

    public enum Error: Swift.Error {
        case closed
    }

    public var closed: Bool

    public init(_ bytes: Bytes) {
        self.bytes = bytes
        index = 0
        closed = false
    }

    public func next(_ max: Int) throws -> BytesSlice {
        guard !closed else {
            throw Error.closed
        }

        var max = max
        if max + index > bytes.count {
            max = bytes.count - index
        }

        let new = bytes.index(index, offsetBy: max)
        let slice = bytes[index..<new]
        index = new

        if index == bytes.count {
            closed = true
        }

        return slice
    }
}
