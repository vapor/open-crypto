import XCTest
import Core
@testable import Cipher
import Random
import Hash

class CipherTests: XCTestCase {
    static var allTests = [
        ("testBlowfish", testBlowfish),
    ]

    func testBlowfish() throws {
        let secret = "vapor"
        let cipher = try Cipher(.blowfish(.cbc), key: "passwordpassword".makeBytes())

        let encrypted = try cipher.encrypt(secret.makeBytes())
        XCTAssertEqual(encrypted.hexString, "7168725af0b510be")

        let decrypted = try cipher.decrypt(encrypted)
        XCTAssertEqual(decrypted.string, secret)
    }

    func testChaCha20() throws {
        let secret = "vapor"
        let cipher = try Cipher(.chacha20, key: "passwordpasswordpasswordpassword".makeBytes(), iv: "password".makeBytes())

        let encrypted = try cipher.encrypt(secret.makeBytes())

        let decrypted = try cipher.decrypt(encrypted)
        XCTAssertEqual(decrypted.string, secret)
    }

    func testOverflow() throws {
        let key = "passwordpasswordpasswordpassword".makeBytes()
        let iv = "passwordpassword".makeBytes()
        let plaintext = try URandom.bytes(count: 65_536)

        let cipher = try Cipher(.aes256(.cbc), key: key, iv: iv)
        let encrypted = try cipher.encrypt(plaintext)
        let decrypted = try cipher.decrypt(encrypted)

        XCTAssertEqual(plaintext, decrypted)
    }
}
