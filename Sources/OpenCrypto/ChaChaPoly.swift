import COpenCrypto

public enum ChaChaPoly: OpenSSLCipherFunction {
    static func algorithm(for key: SymmetricKey) throws -> OpaquePointer {
        guard OpenSSLVersion.current >= .v1_1 else {
            fatalError("ChaChaPoly is not available on OpenSSL < 1.1")
        }
        return convert(EVP_chacha20_poly1305())
    }
}

extension ChaChaPoly {
    public struct Nonce : ContiguousBytes, Sequence, OpenSSLCipherNonce {
        let bytes: [UInt8]

        public init() {
            self.bytes = [UInt8].random(count: 12)
        }

        public init<D>(data: D) throws where D : DataProtocol {
            self.bytes = data.copyBytes()
        }

        public func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
            return try self.bytes.withUnsafeBytes(body)
        }

        public func makeIterator() -> Array<UInt8>.Iterator {
            return self.bytes.makeIterator()
        }
    }
}

extension ChaChaPoly {
    public struct SealedBox: OpenSSLCipherSealedBox {
        public let nonce: Nonce
        public let ciphertext: [UInt8]
        public let tag: [UInt8]

        init(nonce: Nonce, ciphertext: [UInt8], tag: [UInt8]) {
            self.nonce = nonce
            self.ciphertext = ciphertext
            self.tag = tag
        }

        public init?<C, T>(nonce: Nonce, ciphertext: C, tag: T)
            where C: DataProtocol, T: DataProtocol
        {
            self.nonce = nonce
            self.ciphertext = ciphertext.copyBytes()
            self.tag = tag.copyBytes()
        }
    }
}
