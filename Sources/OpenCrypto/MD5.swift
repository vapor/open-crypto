import COpenCrypto

extension Insecure {
    public struct MD5 : OpenSSLHashFunction {
        public typealias Digest = MD5Digest
        let context: OpaquePointer
    }
    
    public struct MD5Digest : OpenSSLDigest {
        static let algorithm: OpaquePointer = EVP_md5()
        let bytes: [UInt8]
    }
}
