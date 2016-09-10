import Core
import Random

extension Hash {
    public static func random(_ m: Method) throws -> Bytes {
        return try random(m, CryptoRandom.self)
    }

    public static func random<R: Random>(_ m: Method, _ r: R.Type) throws -> Bytes {
        let r = r.init()
        return try random(m, r)
    }

    public static func random<R: Random>(_ m: Method, _ r: R) throws -> Bytes {
        let message = r.bytes(64)
        return try Hash.make(m, message)
    }
}
