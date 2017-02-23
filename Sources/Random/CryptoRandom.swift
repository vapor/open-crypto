import CLibreSSL
import Core

public final class CryptoRandom: Random {
    public init() {}

    public func bytes(_ num: Int) -> Bytes {
        var random = Bytes(repeating: 0, count: num)
		guard RAND_bytes(&random, Int32(num)) == 1 else {
			// If the requested number of random bytes couldn't be read,
			// we need to fail fast and hard.
			abort()
		}
        return random
    }
}

public final class PsuedoRandom: Random {
    public init() {}

    public func bytes(_ num: Int) -> Bytes {
        var random = Bytes(repeating: 0, count: num)
		guard RAND_pseudo_bytes(&random, Int32(num)) == 1 else {
			// If the requested number of random bytes couldn't be read,
			// we need to fail fast and hard.
			abort()
		}
        return random
    }
}
