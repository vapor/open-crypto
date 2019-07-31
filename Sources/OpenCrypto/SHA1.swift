import COpenCrypto

extension Insecure {
    public struct SHA1 : OpenSSLHashFunction {
        public typealias Digest = SHA1Digest
        let context: OpaquePointer
    }

    public struct SHA1Digest : OpenSSLDigest {
        static let algorithm: OpaquePointer = convert(EVP_sha1())
        let bytes: [UInt8]
    }
}
