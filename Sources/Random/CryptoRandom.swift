import CLibreSSL
import Core

public final class CryptoRandom: Random {
    public init() {}

    public func bytes(_ num: Int) -> Bytes {
        var random = Bytes(repeating: 0, count: num)
        RAND_bytes(&random, Int32(num))
        return random
    }
}

public final class PsuedoRandom: Random {
    public init() {}

    public func bytes(_ num: Int) -> Bytes {
        var random = Bytes(repeating: 0, count: num)
        RAND_pseudo_bytes(&random, Int32(num))
        return random
    }
}
