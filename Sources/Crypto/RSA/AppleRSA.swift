#if os(macOS)

import Foundation
import Security

extension RSAKeyType {
    var `class`: CFString {
        switch self {
        case .private: return kSecAttrKeyClassPrivate
        case .public: return kSecAttrKeyClassPublic
        }
    }
}

struct AppleRSA {
    static func sign(_ input: Data, for rsa: RSA) throws -> Data {
        if #available(OSX 10.12, *) {
            let key = try rsa.makeSecKey()
            let algorithm: SecKeyAlgorithm = rsa.secAlgorithm
            guard SecKeyIsAlgorithmSupported(key, .sign, algorithm) else {
                fatalError()
            }

            var error: Unmanaged<CFError>?
            guard let signature = SecKeyCreateSignature(
                key,
                algorithm,
                input as CFData,
                &error
            ) as Data? else {
                throw error!.takeRetainedValue() as Error
            }

            return signature
        } else {
            fatalError("macOS 10.12 or later required for RSA")
        }
    }

    static func verify(signature: Data, matches input: Data, for rsa: RSA) throws -> Bool {
        switch rsa.key.type {
        case .private:
            return try sign(input, for: rsa) == signature
        case .public:
            if #available(OSX 10.12, *) {
                let key = try rsa.makeSecKey()
                let algorithm: SecKeyAlgorithm = rsa.secAlgorithm
                guard SecKeyIsAlgorithmSupported(key, .verify, algorithm) else {
                    fatalError()
                }

                var error: Unmanaged<CFError>?
                let value = SecKeyVerifySignature(
                    key,
                    algorithm,
                    input as CFData,
                    signature as CFData,
                    &error
                )
                if let error = error?.takeRetainedValue() {
                    throw error as Error
                }
                return value
            } else {
                fatalError("macOS 10.12 or later required for RSA")
            }
        }
    }
}

extension RSA {
    @available(OSX 10.12, *)
    func makeSecKey() throws -> SecKey {
        let options: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecAttrKeyClass as String: key.type.class,
            kSecAttrKeySizeInBits as String: key.bits
        ]
        var error: Unmanaged<CFError>?
        guard let key = SecKeyCreateWithData(
            key.data as CFData,
            options as CFDictionary,
            &error
        ) else {
            throw error!.takeRetainedValue() as Error
        }
        return key
    }

    @available(OSX 10.12, *)
    var secAlgorithm: SecKeyAlgorithm {
        switch inputFormat {
        case .digest:
            switch paddingScheme {
            case .pkcs1:
                switch hashAlgorithm {
                case .sha1: return .rsaSignatureDigestPKCS1v15SHA1
                case .sha224: return .rsaSignatureDigestPKCS1v15SHA224
                case .sha256: return .rsaSignatureDigestPKCS1v15SHA256
                case .sha384: return .rsaSignatureDigestPKCS1v15SHA384
                case .sha512: return .rsaSignatureDigestPKCS1v15SHA512
                }
            case .pss:
                if #available(OSX 10.13, *) {
                    switch hashAlgorithm {
                    case .sha1: return .rsaSignatureDigestPSSSHA1
                    case .sha224: return .rsaSignatureDigestPSSSHA224
                    case .sha256: return .rsaSignatureDigestPSSSHA256
                    case .sha384: return .rsaSignatureDigestPSSSHA384
                    case .sha512: return .rsaSignatureDigestPSSSHA512
                    }
                } else {
                    fatalError()
                }
            }
        case .message:
            switch paddingScheme {
            case .pkcs1:
                switch hashAlgorithm {
                case .sha1: return .rsaSignatureMessagePKCS1v15SHA1
                case .sha224: return .rsaSignatureMessagePKCS1v15SHA224
                case .sha256: return .rsaSignatureMessagePKCS1v15SHA256
                case .sha384: return .rsaSignatureMessagePKCS1v15SHA384
                case .sha512: return .rsaSignatureMessagePKCS1v15SHA512
                }
            case .pss:
                if #available(OSX 10.13, *) {
                    switch hashAlgorithm {
                    case .sha1: return .rsaSignatureMessagePSSSHA1
                    case .sha224: return .rsaSignatureMessagePSSSHA224
                    case .sha256: return .rsaSignatureMessagePSSSHA256
                    case .sha384: return .rsaSignatureMessagePSSSHA384
                    case .sha512: return .rsaSignatureMessagePSSSHA512
                    }
                } else {
                    fatalError()
                }
            }
        }
    }
}

#endif
