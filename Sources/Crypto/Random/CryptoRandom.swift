import Bits
import CNIOOpenSSL
import Foundation
import Random

/// Uses OpenSSL `RAND_bytes` to generate random data.
public struct CryptoRandom: DataGenerator {
    /// Creates a new `CryptoRandom`.
    public init() {}

    /// See `DataGenerator`.
    public func generateData(count: Int) throws -> Data {
        var random = Bytes(repeating: 0, count: count)
        guard RAND_bytes(&random, Int32(count)) == 1 else {
            // If the requested number of random bytes couldn't be read,
            // we need to throw an error
            throw CryptoError.openssl(identifier: "randBytes", reason: "Could not generate random data")
        }
        return Data(random)
    }
}
