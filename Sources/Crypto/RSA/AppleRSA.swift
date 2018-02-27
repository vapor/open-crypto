#if os(macOS)

import Foundation
import Security

struct AppleRSA {
    static func makeCiphertext(from plaintext: Data, privateKey: Data) throws -> Data {
        if #available(OSX 10.12, *) {
            let options: [String: Any] = [
                kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
                kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
                kSecAttrKeySizeInBits as String: 2048
            ]
            var error: Unmanaged<CFError>?
            guard let privateKey = SecKeyCreateWithData(
                privateKey as CFData,
                options as CFDictionary,
                &error
            ) else {
                throw error!.takeRetainedValue() as Error
            }

            let algorithm: SecKeyAlgorithm = .rsaSignatureMessagePKCS1v15SHA512
            guard SecKeyIsAlgorithmSupported(privateKey, .sign, algorithm) else {
                fatalError()
            }

            guard let signature = SecKeyCreateSignature(
                privateKey,
                algorithm,
                plaintext as CFData,
                &error
            ) as Data? else {
                throw error!.takeRetainedValue() as Error
            }

            return signature
        } else {
            fatalError("macOS 10.12 or later required for RSA")
        }
    }

    static func verifyCiphertext(_ ciphertext: Data, matches plaintext: Data, publicKey: Data) throws -> Bool {
        if #available(OSX 10.12, *) {
            let options: [String: Any] = [
                kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
                kSecAttrKeyClass as String: kSecAttrKeyClassPublic,
                kSecAttrKeySizeInBits as String: 2048
            ]
            var error: Unmanaged<CFError>?
            guard let publicKey = SecKeyCreateWithData(
                publicKey as CFData,
                options as CFDictionary,
                &error
            ) else {
                throw error!.takeRetainedValue() as Error
            }

            let algorithm: SecKeyAlgorithm = .rsaSignatureMessagePKCS1v15SHA512
            guard SecKeyIsAlgorithmSupported(publicKey, .verify, algorithm) else {
                fatalError()
            }

            return SecKeyVerifySignature(
                publicKey,
                algorithm,
                plaintext as CFData,
                ciphertext as CFData,
                &error
            )
        } else {
            fatalError("macOS 10.12 or later required for RSA")
        }
    }
}

#endif
