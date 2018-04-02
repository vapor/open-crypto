/// BCrypt digest. Use the global `BCrypt` convenience variable.
///
///     try BCrypt.hash("vapor", cost: 4)
///
/// See `BCrypt`.
public final class BCryptDigest {
    /// Creates a new `BCryptDigest`. Use the global `BCrypt` convenience variable.
    public init() { }

    /// Creates a BCrypt digest for the supplied data.
    ///
    ///     try BCrypt.hash("vapor", cost: 4)
    ///
    ///  If a `salt` is not supplied, a random one will be generated. You can use a custom salt if desired.
    ///
    ///     try BCrypt.hash("vapor", cost: 12, salt: "passwordpassword")
    ///
    /// - parameters:
    ///     - plaintext: Plaintext data to digest.
    ///     - cost: Desired complexity. Larger `cost` values take longer to hash and verify.
    ///     - salt: Optional salt for this hash. If omitted, a random salt will be generated.
    ///             The salt must be 16-bytes.
    /// - throws: `CryptoError` if hashing fails or if data conversion fails.
    /// - returns: BCrypt hash for the supplied plaintext data.
    public func hash(_ plaintext: LosslessDataConvertible, cost: Int = 12, salt: LosslessDataConvertible? = nil) throws -> Data {
        let config = try BCryptConfig(
            version: .two(.y),
            cost: cost,
            salt: salt?.convertToData() ?? CryptoRandom().generateData(count: 16)
        )
        let digest = try BCryptAlgorithm(config: config).digest(message: plaintext.convertToData())
        let serializer = BCryptSerializer(config: config, digest: digest)
        return serializer.serialize()
    }

    /// Verifies an existing BCrypt hash matches the supplied plaintext value. Verification works by parsing the salt and version from
    /// the existing digest and using that information to hash the plaintext data. If hash digests match, this method returns true.
    ///
    ///     let hash = try BCrypt.hash("vapor", cost: 4)
    ///     try BCrypt.verify("vapor", created: hash) // true
    ///     try BCrypt.verify("foo", created: hash) // false
    ///
    /// - parameters:
    ///     - plaintext: Plaintext data to digest and verify.
    ///     - hash: Existing BCrypt hash to parse version, salt, and digest from.
    /// - throws: `CryptoError` if hashing fails or if data conversion fails.
    /// - returns: `true` if the hash was created from the supplied plaintext data.
    public func verify(_ plaintext: LosslessDataConvertible, created hash: LosslessDataConvertible) throws -> Bool {
        let parser = try BCryptParser(serialized: hash.convertToData())
        let digest = try BCryptAlgorithm(config: parser.parseConfig()).digest(message: plaintext.convertToData())
        return try digest == parser.parseDigest()
    }
}

/// BCrypt digest.
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
