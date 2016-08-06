import XCTest
import Core
@testable import SHA1
import HMAC
import Essentials

class SHA1Tests: XCTestCase {
    static var allTests = [
        ("testBasic", testBasic),
        ("testPerformance", testPerformance),
    ]

    func testBasic() throws {
        // Source: https://en.wikipedia.org/wiki/SHA-1#Example_hashes
        let tests = [
            (
                "The quick brown fox jumps over the lazy dog",
                "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12"
            ),
            (
                "The quick brown fox jumps over the lazy cog",
                "de9f2c7fd25e1b3afad3e85a0bd17d9b100db4b3"
            ),
            (
                "",
                "da39a3ee5e6b4b0d3255bfef95601890afd80709"
            ),
        ]
        
        for test in tests {
            let result = try SHA1.hash(test.0.bytes).hexString.lowercased()
            XCTAssertEqual(result, test.1.lowercased())
        }
        
        // Source: https://github.com/krzyzanowskim/CryptoSwift/blob/swift3-snapshots/CryptoSwiftTests/HashTests.swift
        XCTAssertEqual(
            try SHA1.hash([0x31, 0x32, 0x33]).hexString.lowercased(),
            "40bd001563085fc35165329ea1ff5c5ecbdbbeef"
        )
    }
    
    func testPerformance() {
        let data = Bytes(repeating: Byte.A, count: 10_000)

        // 0.06 debug
        measure {
            let hasher = SHA1(data)
            _ = try! hasher.hash()
        }
    }
    

    func testHMACSHA1() throws {
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
