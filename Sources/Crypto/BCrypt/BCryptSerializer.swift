import Bits
import Foundation

/// Serializes a BCrypt config + digest into a serialized BCrypt hash.
internal final class BCryptSerializer {
    let config: BCryptConfig
    let digest: Data?

    init(config: BCryptConfig, digest: Data? = nil) {
        self.config = config
        self.digest = digest
    }

    func serializeSalt() -> Data {
        var bytes = Data()
        bytes.reserveCapacity(22)

        bytes.append(Byte.dollar)

        // serialize version
        switch config.version {
        case .two(let scheme):
            bytes.append(.two)
            switch scheme {
            case .none:
                break
            case .a:
                bytes.append(.a)
            case .x:
                bytes.append(.x)
            case .y:
                bytes.append(.y)
            }
        }
        bytes.append(.dollar)

        // serialize cost
        if config.cost < 10 {
            bytes.append(.zero)
        }
        bytes.append(contentsOf: config.cost.description.utf8)
        bytes.append(.dollar)

        // serialize encoded salt
        let encodedSalt = BCryptBase64.encode(config.salt, count: 16)
        bytes.append(contentsOf: encodedSalt)

        return bytes
    }

    func serialize() -> Data {
        var bytes = serializeSalt()

        if let digest = digest {
            let encodedDigest = BCryptBase64.encode(digest, count: 23)
            bytes += encodedDigest
        }

        return bytes
    }
}
