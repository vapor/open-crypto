import XCTest
import Core
@testable import Cipher

class CipherTests: XCTestCase {
    static var allTests = [
        ("testBlowfish", testBlowfish),
    ]

    func testBlowfish() throws {
        let secret = "vapor"
        let cipher = try Cipher(.blowfish(.cbc), key: "passwordpassword".bytes)

        let encrypted = try cipher.encrypt(secret.bytes)
        XCTAssertEqual(encrypted.hexString, "7168725af0b510be")

        let decrypted = try cipher.decrypt(encrypted)
        XCTAssertEqual(decrypted.string, secret)
    }

    func testChaCha20() throws {
        let secret = "vapor"
        let cipher = try Cipher(.chacha20, key: "passwordpasswordpasswordpassword".bytes, iv: "password".bytes)

        let encrypted = try cipher.encrypt(secret.bytes)

        let decrypted = try cipher.decrypt(encrypted)
        XCTAssertEqual(decrypted.string, secret)
    }
}
