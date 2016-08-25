import Essentials
import Core

extension Hash {
    public static func random() throws -> Bytes {
        return try random(CryptoRandom.self)
    }

    public static func random<R: Random>(_ r: R.Type) throws -> Bytes {
        let r = r.init()
        return try random(r)
    }

    public static func random<R: Random>(_ r: R) throws -> Bytes {
        let message = r.bytes(64)
        return try Self.hash(message)
    }
}
