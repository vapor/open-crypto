import CTLS

/// Generates cryptographically secure random data using LibreSSL
public final class Random: RandomProtocol, EmptyInitializable {
    public init() {}

    public func bytes(count: Int) throws -> Bytes {
        var random = Bytes(repeating: 0, count: count)
        guard RAND_bytes(&random, Int32(count)) == 1 else {
            // If the requested number of random bytes couldn't be read,
            // we need to throw an error
            throw LibreSSLError(functionName: "RAND_bytes")
        }
        return random
    }
}
