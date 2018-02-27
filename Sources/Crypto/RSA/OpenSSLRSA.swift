#if os(Linux)

import Foundation
import COpenSSL

struct OpenSSLRSA {
    static func makeCiphertext(from plaintext: Data, privateKey: Data) throws -> Data {

    }

    static func verifyCiphertext(_ ciphertext: Data, matches plaintext: Data, publicKey: Data) throws -> Bool {

    }
}

#endif
