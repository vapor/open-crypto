import Core

public protocol Hash {
    static var blockSize: Int { get }
    func hash(_ stream: ByteStream) throws -> ByteStream
}

extension Hash {
    public func hash(_ bytes: Bytes) throws -> Bytes {
        let inputStream = BasicByteStream(bytes: bytes)
        let outputStream = try hash(inputStream)

        var output: Bytes = []
        while !outputStream.closed {
            let next = try outputStream.next(Self.blockSize)
            output += next
        }

        return output
    }
}

public protocol ByteStream {
    var closed: Bool { get }
    func next(_ max: Int) throws -> Bytes
}

public final class BasicByteStream: ByteStream {
    var bytes: Bytes

    public enum Error: Swift.Error {
        case closed
    }

    public var closed: Bool

    public init(bytes: Bytes) {
        self.bytes = bytes
        closed = false
    }

    public func next(_ max: Int) throws -> Bytes {
        guard !closed else {
            throw Error.closed
        }

        var max = max
        if max > bytes.count {
            max = bytes.count
        }

        let temp = bytes[0..<max]
        bytes = Array(bytes[max..<bytes.count])

        print(bytes.count)
        if bytes.count == 0 {
            closed = true
        }

        return Array(temp)
    }
}
