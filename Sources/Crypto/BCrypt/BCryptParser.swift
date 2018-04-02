import Foundation
import Bits

/// Parses serialized BCrypt hashes into version, salt, and digest.
final class BCryptParser {
    let versionData: Data
    let costData: Data
    let encodedSalt: Data
    let encodedDigest: Data?

    init(serialized: Data) throws {
        let parts = serialized.split(separator: .dollar)

        guard parts.count == 3 && (parts[2].count == 22 || parts[2].count == 53) else {
            throw CryptoError(identifier: "invalidBCryptHash", reason: "BCrypt hash format not recognized.")
        }

        versionData = Data(parts[0])
        costData = Data(parts[1])
        if parts[2].count == 22 {
            encodedSalt = Data(parts[2])
            encodedDigest = nil
        } else {
            let rest = Data(parts[2])

            encodedSalt = Data(rest[0..<22])
            encodedDigest = Data(rest[22..<53])
        }
    }

    func parseDigest() throws -> Data? {
        guard let encodedDigest = self.encodedDigest else {
            return nil
        }

        return BCryptBase64.decode(encodedDigest, count: 23)
    }

    func parseConfig() throws -> BCryptConfig {
        let version = try parseVersion()
        let cost = try parseCost()

        let decoded = BCryptBase64.decode(encodedSalt, count: 16)
        return .init(version: version, cost: cost, salt: decoded)
    }

    func parseCost() throws -> Int {
        guard let costString = String(bytes: costData, encoding: .utf8), let cost = Int(costString) else {
            throw CryptoError(identifier: "bcryptInvalidCost", reason: "Invalid BCrypt cost.")
        }
        return cost
    }

    func parseVersion() throws -> BCryptVersion {
        guard versionData.count >= 1 else {
            throw CryptoError(identifier: "bcryptInvalidVersion", reason: "Invalid BCrypt version.")
        }

        let version: BCryptVersion

        switch versionData[0] {
        case Byte.two:
            switch versionData.count {
            case 2:
                switch versionData[1] {
                case Byte.a:
                    version = .two(.a)
                case Byte.x:
                    version = .two(.x)
                case Byte.y:
                    version = .two(.y)
                default:
                    throw CryptoError(identifier: "bcryptInvalidVersion", reason: "Invalid BCrypt version.")
                }
            case 1:
                version = .two(.none)
            default:
                throw CryptoError(identifier: "bcryptInvalidVersion", reason: "Invalid BCrypt version.")
            }
        default:
            throw CryptoError(identifier: "bcryptUnsupportedVersion", reason: "Unsupported BCrypt version.")
        }

        return version
    }
}
