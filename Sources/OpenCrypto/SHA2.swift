import COpenCrypto

public struct SHA256 : OpenSSLHashFunction {
    public typealias Digest = SHA256Digest
    let context: OpaquePointer
}

public struct SHA256Digest : OpenSSLDigest {
    static let algorithm: OpaquePointer = EVP_sha256()
    let bytes: [UInt8]
}

public struct SHA384 : OpenSSLHashFunction {
    public typealias Digest = SHA384Digest
    let context: OpaquePointer
}

public struct SHA384Digest : OpenSSLDigest {
    static let algorithm: OpaquePointer = EVP_sha384()
    let bytes: [UInt8]
}

public struct SHA512 : OpenSSLHashFunction {
    public typealias Digest = SHA512Digest
    let context: OpaquePointer
}

public struct SHA512Digest : OpenSSLDigest {
    static let algorithm: OpaquePointer = EVP_sha512()
    let bytes: [UInt8]
}
