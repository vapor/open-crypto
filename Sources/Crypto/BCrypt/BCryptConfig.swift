/// Internal BCrypt algorithm configuration values
internal struct BCryptConfig {
    public let version: BCryptVersion
    public let cost: Int
    public let salt: Data

    public init(version: BCryptVersion = .two(.y), cost: Int = 12, salt: Data) {
        self.version = version
        self.cost = cost
        self.salt = salt
    }
}

enum BCryptVersion {
    case two(BCryptScheme)
}

enum BCryptScheme {
    case none
    case a
    case x
    case y
}
