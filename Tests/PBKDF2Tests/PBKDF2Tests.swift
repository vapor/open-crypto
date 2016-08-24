import XCTest
import Core
@testable import PBKDF2
import SHA1
import MD5
import HMAC

class PBKDF2Tests: XCTestCase {
    static var allTests = [
        ("testValidation", testValidation),
        ("testSHA1", testSHA1),
        ("testPerformance", testPerformance),
    ]
    
    func testValidation() throws {
        let result = try PBKDF2<SHA1>.derive(fromKey: "vapor".bytes, usingSalt: "V4P012".bytes, iterating: 1000, keyLength: 10)
        
        XCTAssert(try PBKDF2<SHA1>.validate(key: "vapor".bytes, usingSalt: "V4P012".bytes, against: result, iterating: 1000))
    }

    func testSHA1() throws {
        // Source: PHP/produce_tests.php
        let tests: [(key: String, salt: String, expected: String, iterations: Int)] = [
            (
                "password",
                "salt",
                "6e88be8bad7eae9d9e10aa061224034fed48d03f",
                1000
            ),
            (
                "password2",
                "othersalt",
                "7a0363dd39e51c2cf86218038ad55f6fbbff6291",
                1000
            ),
            (
                "somewhatlongpasswordstringthatIwanttotest",
                "1",
                "8cba8dd99a165833c8d7e3530641c0ecddc6e48c",
                1000
            ),
            (
                "p",
                "somewhatlongsaltstringthatIwanttotest",
                "31593b82b859877ea36dc474503d073e6d56a33d",
                1000
            ),
        ]
        
        for test in tests {
            let result = try PBKDF2<SHA1>.derive(fromKey: test.key.bytes, usingSalt: test.salt.bytes, iterating: test.iterations).hexString.lowercased()
            
            XCTAssertEqual(result, test.expected.lowercased())
        }
    }

    func testPerformance() {
        let data = Bytes(repeating: Byte.A, count: 10_000_000)

        // ~0.250 release
        measure {
            let hasher = SHA1(data)
            _ = try! hasher.hash()
        }
    }
    

    func testHMAC() throws {
        let tests: [(key: String, message: String, expected: String)] = [
            (
                "vapor",
                "hello",
                "bb2a9aabb537902647f3f40bfecb679bf0d7d64b"
            ),
            (
                "true",
                "2+2=4",
                "35836a9520eb061ad7e267ac37ab3ee1fafa6e4b"
            )
        ]
        
        for (i, test) in tests.enumerated() {
            do {
                let result = try HMAC<SHA1>().authenticate(
                    test.message.bytes,
                    key: test.key.bytes
                ).hexString.lowercased()
                XCTAssertEqual(result, test.expected.lowercased())
            } catch {
                XCTFail("Test \(i) failed: \(error)")
            }
        }
        
        // Source: https://github.com/krzyzanowskim/CryptoSwift/blob/swift3-snapshots/CryptoSwiftTests/HMACTests.swift
        XCTAssertEqual(
            try HMAC<SHA1>().authenticate([], key: []),
            [0xfb,0xdb,0x1d,0x1b,0x18,0xaa,0x6c,0x08,0x32,0x4b,0x7d,0x64,0xb7,0x1f,0xb7,0x63,0x70,0x69,0x0e,0x1d]
        )
    }

}
