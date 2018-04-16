import Foundation
import Random
import libbcrypt

/// Creates and verifies BCrypt hashes. Normally you will not need to initialize one of these classes and you will
/// use the global `BCrypt` convenience instead.
///
///     try BCrypt.hash("vapor", cost: 4)
///
/// See `BCrypt` for more information.
public final class BCryptDigest {

    enum Algorithm: String, RawRepresentable {
        /// older version
        case _2a = "$2a$"
        /// format specific to the crypt_blowfish BCrypt implementation, identical to `2b` in all but name.
        case _2y = "$2y$"
        /// latest revision of the official BCrypt algorithm, current default
        case _2b = "$2b$"

        /// Salt's length
        var saltCount: Int {
            return 29
        }

        /// Checksum's length
        var checksumCount: Int {
            return 31
        }
    }

    /// Generates string (29 chars total) containing the algorithm information + the cost + base-64 encoded 22 character salt
    ///
    ///     E.g:  $2b$05$J/dtt5ybYUTCJ/dtt5ybYO
    ///           $AA$ => Algorithm
    ///              $CC$ => Cost
    ///                  SSSSSSSSSSSSSSSSSSSSSS => Salt
    ///
    /// Allowed charset for the salt: [./A-Za-z0-9]
    private func generateSalt(cost: UInt, algorithm: Algorithm = ._2y) throws -> String {
        let random = try URandom().generateString(count: 16)

        guard let saltRaw = crypt_gensalt(
            algorithm.rawValue,
            cost,
            random,
            Int32(random.count) //Int32(entropy.utf8.count / MemoryLayout<UInt8>.size)
        ) else {
            throw CryptoError(identifier: "unableToGenerateSalt", reason: "Unable to generate BCrypt salt")
        }

        return String(cString: saltRaw)
    }

    public func hash(_ message: String, cost: UInt = 12) throws -> String {
        let salt = try generateSalt(cost: cost)
        return try hash(message, salt: salt)
    }

    public func hash(_ message: String, cost: UInt = 12, salt: String) throws -> String {
        var pointer: UnsafeMutableRawPointer? = UnsafeMutableRawPointer.allocate(byteCount: 40 * MemoryLayout<UInt8>.stride, alignment: MemoryLayout<UInt8>.alignment)
        var dstPointerSize = Int32(40)

        guard let encryptedRaw = crypt_ra(
            message,
            salt,
            &pointer,
            &dstPointerSize
        ) else {
            throw CryptoError(identifier: "unableToComputeHash", reason: "Unable to compute BCrypt hash")
        }

        return String(cString: encryptedRaw)
    }

    public func verify(_ message: String, created hashed: String) throws -> Bool {

        guard let hashVersion = Algorithm(rawValue: String(hashed.prefix(4)))
            else {
                throw CryptoError(identifier: "invalidHashFormat", reason: "No BCrypt revision information found")
        }

        let hashSalt = String(hashed.prefix(hashVersion.saltCount))
        guard !hashSalt.isEmpty, hashSalt.count == hashVersion.saltCount
            else {
                throw CryptoError(identifier: "invalidHashFormat", reason: "BCrypt salt data not found or has incorrect length")
        }

        let hashChecksum = String(hashed.suffix(hashVersion.checksumCount))
        guard !hashChecksum.isEmpty, hashChecksum.count == hashVersion.checksumCount
            else {
                throw CryptoError(identifier: "invalidHashFormat", reason: "BCrypt hash data not found or has incorrect length")
        }

        let messageHash = try hash(message, salt: hashSalt)
        let messageHashChecksum = String(messageHash.suffix(hashVersion.checksumCount))

        return messageHashChecksum == hashChecksum
    }
}

// MARK: BCrypt
/// Creates and verifies BCrypt hashes.
///
/// Use BCrypt to create hashes for sensitive information like passwords.
///
///     try BCrypt.hash("vapor", cost: 4)
///
/// BCrypt uses a random salt each time it creates a hash. To verify hashes, use the `verify(_:matches)` method.
///
///     let hash = try BCrypt.hash("vapor", cost: 4)
///     try BCrypt.verify("vapor", created: hash) // true
///
/// https://en.wikipedia.org/wiki/Bcrypt
public var BCrypt: BCryptDigest {
    return .init()
}
