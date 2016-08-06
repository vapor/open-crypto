import Core

public protocol Hash {
    static var blockSize: Int { get }
    func hash(_ stream: ByteStream) -> ByteStream
}

extension Hash {
    public func hash(_ bytes: Bytes) -> Bytes {
        let input = BasicByteStream(bytes: bytes)

        var output: Bytes = []
        while let next = hash(input).next(Self.blockSize) {
            output += next
        }

        return output
    }
}

public protocol ByteStream {
    func next(_ max: Int) -> Bytes?
}

public final class BasicByteStream: ByteStream {
    var bytes: Bytes

    public init(bytes: Bytes) {
        self.bytes = bytes
    }

    public func next(_ max: Int) -> Bytes? {
        guard bytes.count > 0 else { return nil }

        var max = max
        if bytes.count > max {
            max = bytes.count
        }

        let temp = bytes[0..<max]
        bytes = Array(bytes[max..<bytes.count])

        return Array(temp)
    }
}
