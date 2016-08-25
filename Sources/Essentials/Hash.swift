import Core

/**
    Protocol for hashing algorithms.
 
    Algorithms that conform to this protocol
    gain convenience extensions for hashing
    and may be used in additional cryptographic
    processes like HMAC.
*/
public protocol Hash {
    /**
        Creates a hasher from a
        stream of bytes.
     
        The most basic byte stream is
        just an array of bytes called BasicByteStream.
    */
    init(_ stream: ByteStream)

    /**
        Creates the message digest
        as an array of bytes.
    */
    func hash() throws -> Bytes
}

/**
    Convenience methods for hashers.
*/
extension Hash {

    /**
        Create the hasher from an array
        of bytes. This will internally
        create a BasicByteStream.
    */
    public init(_ bytes: Bytes) {
        let inputStream = BasicByteStream(bytes)
        self.init(inputStream)
    }

    /**
        Create the hasher from something
        representable as bytes. This will internally
        create a BasicByteStream.
    */
    public init<B: BytesRepresentable>(_ bytes: B) throws {
        self.init(try bytes.makeBytes())
    }

    /**
        Hash an array of bytes without
        initializing a hasher.
    */
    public static func hash(_ bytes: Bytes) throws -> Bytes {
        let hasher = Self(bytes)
        return try hasher.hash()
    }

    /**
        Hash an array of something representable
        as bytes without initializing a hasher.
    */
    public static func hash<B: BytesRepresentable>(_ bytes: B) throws -> Bytes {
        return try hash(try bytes.makeBytes())
    }
}
