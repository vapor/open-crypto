extension BCryptSalt {
    /**
     Creates a new random salt with the specified cost factor. Default cost factor of 10, which is probably
     ~100 ms to hash a password on a modern CPU.
     */
    @available(*, deprecated, message: "Use `init(costFactor: Int?) throws` instead.")
    public init(cost: Int = 10) {
        try! self.init(costFactor: cost)
    }
}

extension BCrypt {
    /**
     Hashes the password (using the UTF8 encoding) with the specified salt.
     */
    @available(*, deprecated, message: "Use `digest` instead.")
    public static func hash(password: String, salt: BCryptSalt = BCryptSalt()) -> String {
        return try! digest(password: password, salt: salt)
    }
}
