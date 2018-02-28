#if os(Linux)

import Foundation
import COpenSSL

extension RSAHashAlgorithm {
    var opensslHash: Int32 {
        switch self {
        case .sha1: return NID_sha1
        case .sha224: return NID_sha224
        case .sha256: return NID_sha256
        case .sha384: return NID_sha384
        case .sha512: return NID_sha512
        }
    }
}

struct OpenSSLRSA {
    static func sign(_ input: Data, for rsa: RSA) throws -> Data {
        let key = try rsa.key.makeOpenSSLKey()

        var siglen: UInt32 = 0
        var sig = Data(
            repeating: 0,
            count: Int(RSA_size(key.cKey))
        )

        switch rsa.paddingScheme {
        case .pkcs1: break
        case .pss: throw RSAError(identifier: "paddingScheme", reason: "RSA PSS not yet supported on Linux. Use PKCS#1.")
        }

        var input = input

        switch rsa.inputFormat {
        case .digest: break // leave input as is
        case .message:
            switch rsa.hashAlgorithm {
            case .sha1: input = SHA1.hash(input)
            case .sha224: input = SHA224.hash(input)
            case .sha256: input = SHA256.hash(input)
            case .sha384: input = SHA384.hash(input)
            case .sha512: input = SHA512.hash(input)
            }
        }

        let ret = RSA_sign(
            rsa.hashAlgorithm.opensslHash,
            input.withUnsafeBytes { $0 },
            UInt32(input.count),
            sig.withUnsafeMutableBytes { $0 },
            &siglen,
            key.cKey
        )

        guard ret == 1 else {
            let errmsg: UnsafeMutablePointer<Int8>? = nil
            ERR_error_string(ERR_get_error(), errmsg)

            let reason: String
            if let e = errmsg {
                reason = String(validatingUTF8: e) ?? "unknown (invalid error message UTF8)"
            } else {
                reason = "unknown"
            }

            throw RSAError(identifier: "paddingScheme", reason: "RSA signing error: \(reason).")
        }

        return sig
    }

    static func verify(signature: Data, matches input: Data, for rsa: RSA) throws -> Bool {
        let key = try rsa.key.makeOpenSSLKey()
        var input = input

        switch rsa.inputFormat {
        case .digest: break // leave input as is
        case .message:
            switch rsa.hashAlgorithm {
            case .sha1: input = SHA1.hash(input)
            case .sha224: input = SHA224.hash(input)
            case .sha256: input = SHA256.hash(input)
            case .sha384: input = SHA384.hash(input)
            case .sha512: input = SHA512.hash(input)
            }
        }

        let result = RSA_verify(
            rsa.hashAlgorithm.opensslHash,
            input.withUnsafeBytes { $0 },
            UInt32(input.count),
            signature.withUnsafeBytes { $0 },
            UInt32(signature.count),
            key.cKey
        )
        return result == 1
    }
}

final class CRSAKey {
    let cKey: UnsafeMutablePointer<rsa_st>

    init(cKey: UnsafeMutablePointer<rsa_st>) {
        self.cKey = cKey
    }

    deinit {
        RSA_free(cKey)
    }
}

extension RSAKey {
    func makeOpenSSLKey() throws -> CRSAKey {
        let cKey = data.withUnsafeBytes { (ptr: UnsafePointer<UInt8>?) -> UnsafeMutablePointer<rsa_st> in
            var vptr = ptr
            let key: UnsafeMutablePointer<rsa_st>
            switch type {
            case .public: key = d2i_RSA_PUBKEY(nil, &vptr, data.count)
            case .private: key = d2i_RSAPrivateKey(nil, &vptr, data.count)
            }
            return key
        }
        return CRSAKey(cKey: cKey)
    }
}

#endif
