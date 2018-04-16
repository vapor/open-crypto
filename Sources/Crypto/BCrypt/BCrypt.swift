import Foundation
import Random
import libbcrypt

public final class BCrypt {

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
    private static func generateSalt(cost: UInt, algorithm: Algorithm = ._2y) -> String? {
        guard let random = try? URandom().generateString(count: 16)
            else { return nil }

        guard let saltRaw = crypt_gensalt(
            algorithm.rawValue,
            cost,
            random,
            Int32(random.count) //Int32(entropy.utf8.count / MemoryLayout<UInt8>.size)
        ) else { return nil }

        return String(cString: saltRaw)
    }

    public static func hash(_ message: String, cost: UInt = 12) -> String? {
        guard let salt = generateSalt(cost: cost)
            else { return nil }

        return hash(message, salt: salt)
    }

    public static func hash(_ message: String, cost: UInt = 12, salt: String) -> String? {
        var pointer: UnsafeMutableRawPointer? = UnsafeMutableRawPointer.allocate(byteCount: 40 * MemoryLayout<UInt8>.stride, alignment: MemoryLayout<UInt8>.alignment)
        var dstPointerSize = Int32(40)

        guard let encryptedRaw = crypt_ra(
            message,
            salt,
            &pointer,
            &dstPointerSize
            ) else { return nil }

        return String(cString: encryptedRaw)
    }

    public static func verify(_ message: String, created hashed: String) -> Bool {

        guard let hashVersion = Algorithm(rawValue: String(hashed.prefix(4)))
            else { return false }

        let hashSalt = String(hashed.prefix(hashVersion.saltCount))
        guard !hashSalt.isEmpty, hashSalt.count == hashVersion.saltCount
            else { return false }

        let hashChecksum = String(hashed.suffix(hashVersion.checksumCount))
        guard !hashChecksum.isEmpty, hashChecksum.count == hashVersion.checksumCount
            else { return false }

        guard let messageHash = hash(message, salt: hashSalt)
            else { return false }

        let messageHashChecksum = String(messageHash.suffix(hashVersion.checksumCount))
        guard !messageHashChecksum.isEmpty
            else { return false }

        return messageHashChecksum == hashChecksum
    }
}
