import Foundation

// MARK: TOTP

/// Generates Time-based One-time Passwords using HMAC.
///
///     let code = TOTP.SHA1.generate(secret: "hi")
///     print(code) "123456"
///
/// You can also generate ranges using `generateRange(...)`.
public struct TOTP {
    /// SHA-1 digest based TOTP.
    public static var SHA1: TOTP { return .init(algorithm: .sha1) }
    
    /// SHA-256 digest based TOTP.
    public static var SHA256: TOTP { return .init(algorithm: .sha256) }
    
    /// SHA-512 (SHA-2) digest based TOTP.
    public static var SHA512: TOTP { return .init(algorithm: .sha512) }
    
    /// `DigestAlgorithm` being used.
    public let algorithm: DigestAlgorithm
    
    /// Creates a new `TOTP` using the supplied `DigestAlgorithm`.
    public init(algorithm: DigestAlgorithm) {
        self.algorithm = algorithm
    }
    
    /// Generates a range of TOTP tokens to a specific degree. This method
    /// calls the `generate(...)` method internally.
    ///
    ///     let codes = try TOTP.SHA1.generateRange(degree: 1, secret: key)
    ///     print(codes) // [String]
    ///
    /// - parameters:
    ///     - degree: Number of codes (in addition to the main code) to generate in both the forward
    ///               and backward direction. This number must be at least 1. For each degree, the total
    ///               code count will be increased by two: one for an additional degree in the positive
    ///               and negative offset directions.
    ///               For example, if `degree` is `2`, there will be `5` codes returned: The main code,
    ///               two codes at offset 1 (1 and -1), and two codes at offset 2 (2 and -2).
    ///     - digits: Number of digits to include in the password.
    ///               Defaults to six.
    ///     - secret: Cleartext (_not_ Base32 encoded) secret key.
    ///     - date: Date to generate the TOTP for. This will be divided into intervals automatically.
    public func generateRange(degree: Int, digits: OTPDigits = .six, secret: CustomDataConvertible, at date: Date = .init()) throws -> [String] {
        var res: [String] = try [
            generate(digits: digits, secret: secret, offset: 0, at: date)
        ]
        for i in 1...degree {
            try res.append(generate(digits: digits, secret: secret, offset: i, at: date))
            try res.append(generate(digits: digits, secret: secret, offset: -1 * i, at: date))
        }
        return res
    }
    
    /// Generates a single TOTP.
    ///
    ///     let code = TOTP.SHA1.generate(secret: "hi")
    ///     print(code) "123456"
    ///
    /// - parameters:
    ///     - digits: Number of digits to include in the password.
    ///               Defaults to six.
    ///     - secret: Cleartext (_not_ Base32 encoded) secret key.
    ///     - offset: Specific offset (in intervals) from the supplied date.
    ///               Defaults to 0.
    ///     - date: Date to generate the TOTP for. This will be divided into intervals automatically.
    public func generate(digits: OTPDigits = .six, secret: CustomDataConvertible, offset: Int = 0, at date: Date = .init()) throws -> String {
        let counter = floor(floor(date.timeIntervalSince1970) / 30)
        return try generateOTP(secret: secret, algorithm: algorithm, counter: UInt(counter - Double(offset)), digits: digits)
    }
}

// MARK: HOTP

/// Generates Counter-based One-time Passwords using HMAC.
///
///     let code = HOTP.SHA1.generate(secret: "hi", counter: 0)
///     print(code) "208503"
///
/// See `TOTP` for time-based passwords.
public struct HOTP {
    /// SHA-1 digest based HOTP.
    public static var SHA1: HOTP { return .init(algorithm: .sha1) }
    
    /// SHA-256 digest based HOTP.
    public static var SHA256: HOTP { return .init(algorithm: .sha256) }
    
    /// SHA-512 (SHA-2) digest based HOTP.
    public static var SHA512: HOTP { return .init(algorithm: .sha512) }
    
    /// the specific `DigestAlgorithm`.
    public let algorithm: DigestAlgorithm
    
    /// Creates a new `HOTP` using the supplied `DigestAlgorithm`.
    public init(algorithm: DigestAlgorithm) {
        self.algorithm = algorithm
    }
    
    /// Generates a single HOTP.
    ///
    ///     let code = HOTP.SHA1.generate(secret: "hi", counter: 0)
    ///     print(code) "208503"
    ///
    /// - parameters:
    ///     - digits: Number of digits to include in the password.
    ///               Defaults to six.
    ///     - secret: Cleartext (_not_ Base32 encoded) secret key.
    ///     - counter: Password offset.
    public func generate(digits: OTPDigits = .six, secret: CustomDataConvertible, counter: UInt) throws -> String {
        return try generateOTP(secret: secret, algorithm: algorithm, counter: counter, digits: digits)
    }
}

// MARK: OTP

/// Supported OTP password length.
public enum OTPDigits: Int {
    /// Six digit password.
    case six = 6
    /// Seven digit password.
    case seven = 7
    /// Eight digit password.
    case eight = 8
    
    /// Returns 10^digit
    internal var pow: UInt32 {
        switch self {
        case .six: return 1_000_000
        case .seven: return 10_000_000
        case .eight: return 100_000_000
        }
    }
}

// MARK: Private

private func generateOTP(secret: CustomDataConvertible, algorithm: DigestAlgorithm = .sha1, counter: UInt, digits: OTPDigits) throws -> String {
    let digest = try HMAC(algorithm: algorithm).authenticate(counter.bigEndian.data, key: secret)
    // get last 4 bits of hash for use as offset
    let offset = Int(digest[digest.count - 1] & 0x0f)
    // get 4 bytes of the hash using offset
    let subdigest = Data(digest[offset...offset + 3])
    // convert data to UInt32
    var num = subdigest!.withUnsafeBytes { $0.baseAddress!.assumingMemoryBound(to: UInt32.self).pointee.bigEndian }
    // remove most sig bit
    num &= 0x7fffffff
    // modulo num by digits
    num = num % digits.pow
    // convert to readable num
    let desc = num.description
    return String(repeating: "0", count: digits.rawValue - desc.count) + desc
    
}

private extension FixedWidthInteger {
    var data: Data {
        var int = self
        return .init(bytes: &int, count: MemoryLayout<Self>.size)
    }
}
