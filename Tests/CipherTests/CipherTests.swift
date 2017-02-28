import XCTest
import Core
@testable import Cipher
import Random
import Hash
import CLibreSSL

fileprivate let random = URandom()

class CipherTests: XCTestCase {
    private let plainText = try! random.bytes(count: 65_536)

    static var allTests = [
        ("testBlowfish", testBlowfish),
        ("testCipherStability", testCipherStability)
    ]

    func testBlowfish() throws {
        let secret = "vapor"
        let cipher = try Cipher(.blowfish(.cbc), key: "passwordpassword".bytes)

        let encrypted = try cipher.encrypt(secret.bytes)
        XCTAssertEqual(encrypted.hexString, "7168725af0b510be")

        let decrypted = try cipher.decrypt(encrypted)
        XCTAssertEqual(decrypted.string, secret)
    }

    func testCipherStability() {
        var methods: [Cipher.Method] = [.chacha20]
        methods.append(contentsOf: [.cbc, .ecb, .ofb, .cfb64].map { .blowfish($0) })
        // TODO: .cbcHMACSHA1 crashes as EVP_aes_128_cbc_hmac_sha1() returns nil on OSX!
        methods.append(contentsOf: [.cbc, .cfb1, .cfb128, .cfb8, .ctr, .ecb, .gcm, .ofb, .xts].map { .aes128($0) })
        methods.append(contentsOf: [.cbc, .cfb1, .cfb128, .cfb8, .ctr, .ecb, .gcm, .ofb].map { .aes192($0) })
        // TODO: .cbcHMACSHA1 crashes as EVP_aes_256_cbc_hmac_sha1() returns nil on OSX!
        methods.append(contentsOf: [.cbc, .cfb1, .cfb128, .cfb8, .ctr, .ecb, .gcm, .ofb, .xts].map { .aes256($0) })
        methods.append(contentsOf: [.ecb, .ofb, .cbc, .cfb64, .fortyCBC, .sixtyFourCBC].map { .rc2($0) })
        methods.append(contentsOf: [.none, .forty, .hmacMD5].map { .rc4($0) })
        methods.append(contentsOf: [.ecb, .ofb, .cbc, .cfb64].map { .idea($0) })
        methods.append(contentsOf: [.ecb, .ofb, .cbc, .cfb64].map { .cast5($0) })
        methods.append(contentsOf: [.ecb, .cbc, .cfb1, .cfb8, .cfb128].map { .camellia128($0) })
        methods.append(contentsOf: [.ecb, .cbc, .cfb1, .cfb8, .cfb128].map { .camellia192($0) })
        methods.append(contentsOf: [.ecb, .cbc, .cfb1, .cfb8, .cfb128].map { .camellia256($0) })
        methods.append(contentsOf: [.ecb, .cfb64, .cnt].map { .gost2814789($0) })
        methods.append(contentsOf: [.cfb1, .cfb8, .cfb64, .ofb, .ecb, .cbc].map { .des(.none($0)) })
        methods.append(contentsOf: [.none, .cfb64, .ofb, .ecb, .cbc].map { .des(.ede($0)) })
        methods.append(contentsOf: [.none, .cfb1, .cfb8, .cfb64, .ofb, .ecb, .cbc].map { .des(.ede3($0)) })
        methods.forEach { self.testStability(of: $0) }
    }

    private func testStability(of method: Cipher.Method) {
        let keyLen = Int(EVP_CIPHER_key_length(method.evp))
        let ivLen = Int(EVP_CIPHER_iv_length(method.evp))

        guard let key = try? random.bytes(count: keyLen) else {
            fatalError("Failed to generate \(keyLen) bytes for a random key")
        }
        
        guard let iv = try? random.bytes(count: ivLen) else {
            fatalError("Failed to generate \(keyLen) bytes for a random IV")
        }

        let cipher: Cipher

        do {
            cipher = try Cipher(method, key: key, iv: iv)
        } catch {
            XCTFail("Cipher \(method) - setup failed: \(error)")
            return
        }

        let encrypted: Bytes
        let decrypted: Bytes

        do {
            encrypted = try cipher.encrypt(plainText)
        } catch {
            XCTFail("Cipher \(method) - encryption failed: \(error)")
            return
        }
        
        do {
            decrypted = try cipher.decrypt(encrypted)
        } catch {
            XCTFail("Cipher \(method) - decryption failed: \(error)")
            return
        }
        
        XCTAssert(decrypted == plainText, "Cipher \(method) - incorrect results")
    }
}
