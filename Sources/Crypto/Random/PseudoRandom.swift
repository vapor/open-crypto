import CLibreSSL

/// Generates non-secure pseudorandom data using LibreSSL
public final class PseudoRandom: RandomProtocol, EmptyInitializable {
    public init() {}

    public func bytes(count: Int) throws -> Bytes {
        var random = Bytes(repeating: 0, count: count)
        guard RAND_pseudo_bytes(&random, Int32(count)) == 1 else {
            // If the requested number of random bytes couldn't be read,
            // we need to throw an error
            throw LibreSSLError(functionName: "RAND_pseudo_bytes")
        }
        return random
    }
}
