import Core
import Random

public var defaultCost: UInt = 10

public struct Salt {
    public enum Version {
        case two(Scheme)

        public enum Scheme {
            case none
            case a
            case x
            case y
        }
    }

    public let version: Version
    public let cost: UInt
    public let bytes: Bytes

    public init(_ version: Version = .two(.y), cost: UInt = defaultCost, bytes: Bytes? = nil) throws {
        let bytes = try bytes ?? CryptoRandom.bytes(count: 16)

        guard bytes.count == 16 else {
            throw BCryptError.invalidSaltByteCount
        }

        self.version = version
        self.cost = cost
        self.bytes = bytes
    }

    /// String representation of the BCrypt Salt
    public var string: String {
        return "$2a$\(cost.description)$\(bytes.base64Encoded[0..<22].string)"
    }
}

public enum BCryptError: Error {
    case noDigest
    case invalidDigest
    case invalidSalt
    case invalidSaltByteCount
    case invalidSaltVersion
    case invalidSaltCost
    case saltBase64DecodeFailure
    case unsupportedSaltVersion
}
