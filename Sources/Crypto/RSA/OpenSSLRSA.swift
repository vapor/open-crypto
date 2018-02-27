#if os(Linux)

import Foundation
import COpenSSL

struct OpenSSLRSA {
    static func sign(_ input: Data, for rsa: RSA) throws -> Data {
        let key = try rsa.key.makeOpenSSLKey()

        // verify private

        var siglen: UInt32 = 0
        var sig = [UInt8](
            repeating: 0,
            count: Int(RSA_size(key.cKey))
        )

        let digest = try Hash(hashMethod.method, message).hash()

        let ret = RSA_sign(
            hashMethod.type,
            digest,
            UInt32(digest.count),
            &sig,
            &siglen,
            cKey
        )

        guard ret == 1 else {
            let reason: UnsafeMutablePointer<Int8>? = nil
            ERR_error_string(ERR_get_error(), reason)
            if let reason = reason {
                let string = String(validatingUTF8: reason) ?? ""
                print("[JWT] Signing error: \(string)")
            }
            throw JWTError.signing
        }

        return sig
    }

    static func verify(signature: Data, matches input: Data, for rsa: RSA) throws -> Bool {
        let key = try rsa.key.makeOpenSSLKey()

    }
}

final class CRSAKey {
    let cKey: UnsafeMutablePointer<RSA>

    init(cKey: UnsafeMutablePointer<RSA>) {
        self.cKey = cKey
    }

    deinit {
        RSA_free(cKey)
    }
}

extension RSAKey {
    func makeOpenSSLKey() throws -> CRSAKey {
        let maybeKey = data.withUnsafeBufferPointer { ptr -> UnsafeMutablePointer<RSA>? in
            var base = ptr.baseAddress
            switch type {
            case .public: return d2i_RSA_PUBKEY(nil, &base, data.count)
            case .private: return d2i_RSAPrivateKey(nil, &base, data.count)
            }
        }

        guard let cKey = maybeKey else {
            fatalError()
        }
        return CRSAKey(cKey: cKey)
    }
}

#endif
