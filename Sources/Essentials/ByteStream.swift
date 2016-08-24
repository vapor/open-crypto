import Core

public protocol ByteStream {
    var closed: Bool { get }
    func next() throws -> Bytes
}

public final class BasicByteStream: ByteStream {
    let bytes: Bytes

    public enum Error: Swift.Error {
        case closed
    }

    public var closed: Bool

    public init(_ bytes: Bytes) {
        self.bytes = bytes
        closed = false
    }

    public func next() throws -> Bytes {
        guard !closed else {
            throw Error.closed
        }

        closed = true
        return bytes
    }
}
