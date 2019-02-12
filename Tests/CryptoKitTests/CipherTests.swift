import XCTest
import CryptoKit

class CipherTests: XCTestCase {
    func testAES256Basic() throws {
        let message = "vapor"
        let key = "passwordpasswordpasswordpassword"
        let iv = "passwordpassword"
        let ciphertext = try AES256CBC.encrypt(message, key: key, iv: iv)
        XCTAssertEqual(ciphertext.hexEncodedString(), "0c0beecdc724b2b79a14c4d1e49d0de6")
        try XCTAssertEqual(AES256CBC.decrypt(ciphertext, key: key, iv: iv).convert(), message)
    }
    
    func testAES256WellKnownDecode() throws {
        let key = "passwordpasswordpasswordpassword"
        let iv = "passwordpassword"
        let ciphertext = Data(bytes: [0x0c, 0x0b, 0xee, 0xcd, 0xc7, 0x24, 0xb2, 0xb7, 0x9a, 0x14, 0xc4, 0xd1, 0xe4, 0x9d, 0x0d, 0xe6])
        try XCTAssertEqual(AES256CBC.decrypt(ciphertext, key: key, iv: iv).convert(), "vapor")
    }
    
    func testCipherReuse() throws {
        let cipher = AES256CBC
        do {
            let message = "vapor1"
            let key = "passwordpasswor1passwordpasswor1"
            let iv = "passwordpassword"
            let ciphertext = try cipher.encrypt(message, key: key, iv: iv)
            XCTAssertEqual(ciphertext.hexEncodedString(), "1a66ca18f527d803c7da9aa947e23522")
            try XCTAssertEqual(cipher.decrypt(ciphertext, key: key, iv: iv).convert(), message)
        }
        do {
            let message = "vapor2"
            let key = "passwordpasswor2passwordpasswor2"
            let iv = "passwor1passwor2"
            let ciphertext = try cipher.encrypt(message, key: key, iv: iv)
            XCTAssertEqual(ciphertext.hexEncodedString(), "2359dbd0d34fa59d64f2316113a54330")
            try XCTAssertEqual(cipher.decrypt(ciphertext, key: key, iv: iv).convert(), message)
        }
    }

    func testAES256GCM() throws {
        let message = "vapor"
        let key = "passwordpasswordpasswordpassword"
        let iv = "123456789012"
        let (ciphertext, tag) = try AES256GCM.encrypt(message, key: key, iv: iv)
        XCTAssertEqual(ciphertext.hexEncodedString(), "4fa166802c")
        try XCTAssertEqual(AES256GCM.decrypt(ciphertext, key: key, iv: iv, tag: tag).convert(), message)
    }

    func testAES256GCMAuthenticationFailure() throws {
        let message = "vapor"
        let key = "passwordpasswordpasswordpassword"
        let iv = "123456789012"
        var (ciphertext, tag) = try AES256GCM.encrypt(message, key: key, iv: iv)
        XCTAssertEqual(ciphertext.hexEncodedString(), "4fa166802c")

        // Forcibly overwrite bytes in the tag data to fail authentication
        tag[2] = 0
        tag[3] = 1
        tag[4] = 2

        XCTAssertThrowsError(try AES256GCM.decrypt(ciphertext, key: key, iv: iv, tag: tag))
    }

    func testAES256GCMShortTag() throws {
        let message = "vapor"
        let key = "passwordpasswordpasswordpassword"
        let iv = "123456789012"
        var (ciphertext, tag) = try AES256GCM.encrypt(message, key: key, iv: iv)
        XCTAssertEqual(ciphertext.hexEncodedString(), "4fa166802c")

        // Delete one byte from the tag to force short-tag authentication failure
        tag.remove(at: 2)

        XCTAssertThrowsError(try AES256GCM.decrypt(ciphertext, key: key, iv: iv, tag: tag))
    }

    static var allTests = [
        ("testAES256Basic", testAES256Basic),
        ("testAES256WellKnownDecode", testAES256WellKnownDecode),
        ("testCipherReuse", testCipherReuse),
        ("testAES256GCM", testAES256GCM),
        ("testAES256GCMShortTag", testAES256GCMShortTag),
        ("testAES256GCMAuthenticationFailure", testAES256GCMAuthenticationFailure),
    ]
}

extension Data {
    public func convert<T>(to type: T.Type = T.self) -> T where T: LosslessDataConvertible {
        return T(self)!
    }
}
