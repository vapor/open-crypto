import COpenCrypto

public enum AES {
    public enum GCM {
        public static func seal<Plaintext>(
            _ message: Plaintext,
            using key: SymmetricKey,
            nonce: Nonce? = nil
        ) throws -> SealedBox
            where Plaintext : DataProtocol
        {
            let algorithm: OpaquePointer
            switch key.bitCount {
            case 128:
                algorithm = EVP_aes_128_gcm()
            case 192:
                algorithm = EVP_aes_192_gcm()
            case 256:
                algorithm = EVP_aes_256_gcm()
            default:
                fatalError("Unsupported key size: \(key.bitCount)")
            }
            let nonce = nonce ?? Nonce()
            let cipher = OpenSSLCipher(algorithm: algorithm)
            var buffer = [UInt8]()
            cipher.reset(key: key, iv: nonce.bytes, mode: .encrypt)
            cipher.update(data: message, into: &buffer)
            cipher.finish(into: &buffer)
            return SealedBox(nonce: nonce, ciphertext: buffer, tag: cipher.getTag())!
        }

        public static func open(
            _ sealedBox: SealedBox,
            using key: SymmetricKey
        ) throws -> [UInt8] {
            let algorithm: OpaquePointer
            switch key.bitCount {
            case 128:
                algorithm = EVP_aes_128_gcm()
            case 192:
                algorithm = EVP_aes_192_gcm()
            case 256:
                algorithm = EVP_aes_256_gcm()
            default:
                fatalError("Unsupported key size: \(key.bitCount)")
            }
            let cipher = OpenSSLCipher(algorithm: algorithm)
            var buffer = [UInt8]()
            cipher.reset(key: key, iv: sealedBox.nonce.bytes, mode: .decrypt)
            cipher.setTag(sealedBox.tag)
            cipher.update(data: sealedBox.ciphertext, into: &buffer)
            cipher.finish(into: &buffer)
            return buffer
        }
    }
}

extension AES.GCM {
    public struct Nonce : ContiguousBytes, Sequence {
        let bytes: [UInt8]

        public init() {
            self.bytes = [UInt8].random(count: 16)
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

extension AES.GCM {
    public struct SealedBox {
        public let nonce: Nonce
        public let ciphertext: [UInt8]
        public let tag: [UInt8]

        public init?<C, T>(nonce: Nonce, ciphertext: C, tag: T)
            where C: DataProtocol, T: DataProtocol
        {
            self.nonce = nonce
            self.ciphertext = ciphertext.copyBytes()
            self.tag = tag.copyBytes()
        }
    }
}
