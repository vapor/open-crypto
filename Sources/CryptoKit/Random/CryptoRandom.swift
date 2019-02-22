import CCryptoOpenSSL
import Foundation

/// Uses OpenSSL `RAND_bytes` to generate random data.
///
/// - warning: The underlying implementation uses `RAND_bytes` which has [been shown]( http://emboss.github.io/blog/2013/08/21/openssl-prng-is-not-really-fork-safe/)
///            to not be fork safe. Consider using `URandom` instead.
public struct CryptoRandom: DataGenerator {
    /// Creates a new `CryptoRandom`.
    public init() {}

    /// See `DataGenerator`.
    public func generateData(count: Int) throws -> [UInt8] {
        var random = [UInt8](repeating: 0, count: count)
        guard RAND_bytes(&random, Int32(count)) == 1 else {
            // If the requested number of random bytes couldn't be read,
            // we need to throw an error
            throw CryptoError.openssl(identifier: "randBytes", reason: "Could not generate random data")
        }
        return random
    }
}
