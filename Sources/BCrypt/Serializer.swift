import Core

public final class Serializer {
    let salt: Salt
    let digest: Bytes?

    public init(_ salt: Salt, digest: Bytes? = nil) {
        self.salt = salt
        self.digest = digest
    }

    public func serializeSalt() -> Bytes {
        var bytes: Bytes = [.dollar]

        // serialize version
        switch salt.version {
        case .two(let scheme):
            bytes += .two
            switch scheme {
            case .none:
                break
            case .a:
                bytes += .a
            case .x:
                bytes += .x
            case .y:
                bytes += .y
            }
        }
        bytes += .dollar

        // serialize cost
        if salt.cost < 10 {
            bytes += .zero
        }
        bytes += salt.cost.description.makeBytes()
        bytes += .dollar

        // serialize encoded salt
        let encodedSalt = Base64.encode(salt.bytes, count: 16)
        bytes += encodedSalt

        return bytes
    }

    public func serialize() -> Bytes {
        var bytes = serializeSalt()

        if let digest = digest {
            let encodedDigest = Base64.encode(digest, count: 23)
            bytes += encodedDigest
        }

        return bytes
    }
}
