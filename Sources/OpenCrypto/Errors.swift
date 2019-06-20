public enum CipherError : Error, Equatable, Hashable {
    case internalError
    case incorrectTag
}

public enum CryptoKitError : Error {
    case incorrectKeySize
    case incorrectParameterSize
    case underlyingCoreCryptoError(error: Int32)
}
