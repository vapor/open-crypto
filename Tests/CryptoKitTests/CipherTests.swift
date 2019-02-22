import XCTest
import CryptoKit

public class CipherTests: XCTestCase {
    public func testAES256Basic() throws {
        let message: CryptoData = "vapor"
        let key: CryptoData = "passwordpasswordpasswordpassword"
        let iv: CryptoData = "passwordpassword"
        let ciphertext = try AES256CBC.encrypt(message, key: key, iv: iv)
        XCTAssertEqual(ciphertext.hexEncodedString(), "0c0beecdc724b2b79a14c4d1e49d0de6")
        try XCTAssertEqual(AES256CBC.decrypt(ciphertext, key: key, iv: iv), message)
    }
    
    public func testAES256WellKnownDecode() throws {
        let key: CryptoData = "passwordpasswordpasswordpassword"
        let iv: CryptoData = "passwordpassword"
        let ciphertext: CryptoData = .bytes([0x0c, 0x0b, 0xee, 0xcd, 0xc7, 0x24, 0xb2, 0xb7, 0x9a, 0x14, 0xc4, 0xd1, 0xe4, 0x9d, 0x0d, 0xe6])
        try XCTAssertEqual(AES256CBC.decrypt(ciphertext, key: key, iv: iv), "vapor")
    }
    
    public func testCipherReuse() throws {
        let cipher = AES256CBC
        do {
            let message: CryptoData = "vapor1"
            let key: CryptoData = "passwordpasswor1passwordpasswor1"
            let iv: CryptoData = "passwordpassword"
            let ciphertext = try cipher.encrypt(message, key: key, iv: iv)
            XCTAssertEqual(ciphertext.hexEncodedString(), "1a66ca18f527d803c7da9aa947e23522")
            try XCTAssertEqual(cipher.decrypt(ciphertext, key: key, iv: iv), message)
        }
        do {
            let message: CryptoData = "vapor2"
            let key: CryptoData = "passwordpasswor2passwordpasswor2"
            let iv: CryptoData = "passwor1passwor2"
            let ciphertext = try cipher.encrypt(message, key: key, iv: iv)
            XCTAssertEqual(ciphertext.hexEncodedString(), "2359dbd0d34fa59d64f2316113a54330")
            try XCTAssertEqual(cipher.decrypt(ciphertext, key: key, iv: iv), message)
        }
    }

    public func testAES256GCM() throws {
        let message: CryptoData = "vapor"
        let key: CryptoData = "passwordpasswordpasswordpassword"
        let iv: CryptoData = "123456789012"
        let (ciphertext, tag) = try AES256GCM.encrypt(message, key: key, iv: iv)
        XCTAssertEqual(ciphertext.hexEncodedString(), "4fa166802c")
        try XCTAssertEqual(AES256GCM.decrypt(ciphertext, key: key, iv: iv, tag: tag), message)
    }

    public func testAES256GCMAuthenticationFailure() throws {
        let message: CryptoData = "vapor"
        let key: CryptoData = "passwordpasswordpasswordpassword"
        let iv: CryptoData = "123456789012"
        let (ciphertext, tag) = try AES256GCM.encrypt(message, key: key, iv: iv)
        XCTAssertEqual(ciphertext.hexEncodedString(), "4fa166802c")

        // Forcibly overwrite bytes in the tag data to fail authentication
        var invalidTag = tag.bytes()
        invalidTag[2] = 0
        invalidTag[3] = 1
        invalidTag[4] = 2

        XCTAssertThrowsError(try AES256GCM.decrypt(ciphertext, key: key, iv: iv, tag: .bytes(invalidTag)))
    }

    public func testAES256GCMShortTag() throws {
        let message: CryptoData = "vapor"
        let key: CryptoData = "passwordpasswordpasswordpassword"
        let iv: CryptoData = "123456789012"
        let (ciphertext, tag) = try AES256GCM.encrypt(message, key: key, iv: iv)
        XCTAssertEqual(ciphertext.hexEncodedString(), "4fa166802c")

        // Delete one byte from the tag to force short-tag authentication failure
        var invalidTag = tag.bytes()
        invalidTag.remove(at: 2)

        XCTAssertThrowsError(try AES256GCM.decrypt(ciphertext, key: key, iv: iv, tag: .bytes(invalidTag)))
    }

    public static var allTests = [
        ("testAES256Basic", testAES256Basic),
        ("testAES256WellKnownDecode", testAES256WellKnownDecode),
        ("testCipherReuse", testCipherReuse),
        ("testAES256GCM", testAES256GCM),
        ("testAES256GCMShortTag", testAES256GCMShortTag),
        ("testAES256GCMAuthenticationFailure", testAES256GCMAuthenticationFailure),
    ]
}
