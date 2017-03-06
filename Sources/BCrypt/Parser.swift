import Core

public final class Parser {
    let versionBytes: Bytes
    let costBytes: Bytes
    let encodedSalt: Bytes
    let encodedDigest: Bytes?

    public init(_ bytes: Bytes) throws {
        let parts = bytes.split(separator: .dollar)

        guard
            parts.count == 3 &&
            (parts[2].count == 22 || parts[2].count == 53)
        else {
            throw BCryptError.invalidDigest
        }

        versionBytes = parts[0].array
        costBytes = parts[1].array
        if parts[2].count == 22 {
            encodedSalt = parts[2].array
            encodedDigest = nil
        } else {
            let rest = parts[2].array

            encodedSalt = rest[0..<22].array
            encodedDigest = rest[22..<53].array
        }
    }

    public func parseDigest() throws -> Bytes {
        guard let encodedDigest = self.encodedDigest else {
            throw BCryptError.invalidSalt
        }

        return Base64.decode(encodedDigest, count: 23)
    }

    public func parseSalt() throws -> Salt {
        let version = try parseVersion()
        let cost = try parseCost()

        let decoded = Base64.decode(encodedSalt, count: 16)
        return try Salt(version, cost: UInt(cost), bytes: decoded)
    }

    public func parseCost() throws -> UInt {
        guard let cost = costBytes.decimalInt else {
            throw BCryptError.invalidSaltCost
        }

        return UInt(cost)
    }

    public func parseVersion() throws -> Salt.Version {
        guard versionBytes.count >= 1 else {
            throw BCryptError.invalidSaltVersion
        }

        let version: Salt.Version

        switch versionBytes[0] {
        case Byte.two:
            switch versionBytes.count {
            case 2:
                switch versionBytes[1] {
                case Byte.a:
                    version = .two(.a)
                case Byte.x:
                    version = .two(.x)
                case Byte.y:
                    version = .two(.y)
                default:
                    throw BCryptError.invalidSaltVersion
                }
            case 1:
                version = .two(.none)
            default:
                throw BCryptError.invalidSaltVersion
            }
        default:
            throw BCryptError.unsupportedSaltVersion
        }

        return version
    }
}

extension Parser {
    public convenience init(_ bytes: BytesConvertible) throws {
        try self.init(bytes.makeBytes())
    }
}
