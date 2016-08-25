import Core

/**
    Represents a stream of bytes that
    can be passed to cryptographic
    processes like hashers.
*/
public protocol ByteStream {
    /**
        When the stream is closed,
        the crypto process will
        stop requesting bytes.
    */
    var closed: Bool { get }

    /**
        Called by crypto processes in
        a loop until the stream closes.
    */
    func next() throws -> Bytes
}

/**
    The most basic ByteStream consists
    of an array of bytes.
*/
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
