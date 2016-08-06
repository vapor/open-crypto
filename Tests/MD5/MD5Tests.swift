import XCTest
import Core
@testable import MD5
@testable import HMAC
/*
class MD5Tests: XCTestCase {
    static var allTests = [
        ("testMD5", testMD5),
        ("testStreamingMD5performance", testStreamingMD5performance),
        ("testBulkMD5performance", testBulkMD5performance),
        ("testHMACMD5", testHMACMD5),
    ]

    func testMD5() {
        // Source: https://github.com/bcgit/bc-java/blob/adecd89d33edf278a5c601af2de696f0a6f65251/core/src/test/java/org/bouncycastle/crypto/test/MD5DigestTest.java
        let tests = [
            ("", "d41d8cd98f00b204e9800998ecf8427e"),
            ("a", "0cc175b9c0f1b6a831c399e269772661"),
            ("abc", "900150983cd24fb0d6963f7d28e17f72"),
            ("abcdefghijklmnopqrstuvwxyz", "c3fcd3d76192e4007dfb496cca67e13b")
        ]
        
        for test in tests {
            let result = MD5.hash(test.0.bytes).hexString.lowercased()
            XCTAssertEqual(result, test.1.lowercased())
        }
    }
    
    func testStreamingMD5performance() {
        let data = [UInt8](repeating: Byte.A, count: 50000000)
        
        let nonStreamingResult = MD5.hash(data)
        var streamingResult: [UInt8]!
        
        measure {
            let MD5stream = MD5()
            
            for i in 0..<(data.count/1000) {
                MD5stream.append(bytes: Array(data[i*1000..<(i+1)*1000]))
            }
            
            streamingResult = MD5stream.complete()
        }
        
        XCTAssertEqual(nonStreamingResult, streamingResult)
    }
    
    func testBulkMD5performance() {
        let data = [UInt8](repeating: Byte.A, count: 50000000)
        
        measure {
            _ = MD5.hash(data)
        }
    }

    func testHMACMD5() {
        // Source: https://github.com/bcgit/bc-java/blob/adecd89d33edf278a5c601af2de696f0a6f65251/core/src/test/java/org/bouncycastle/crypto/test/MD5HMacTest.java
        let tests = [
            (
                "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
                "Hi There",
                "9294727a3638bb1c13f48ef8158bfc9d",
                false
            ),
            (
                "4a656665",
                "what do ya want for nothing?",
                "750c783e6ab0b503eaa86e310a5db738",
                false
            ),
            (
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
                "56be34521d144c88dbb8c733f0e8b3f6",
                true
            ),
            (
                "0102030405060708090a0b0c0d0e0f10111213141516171819",
                "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd",
                "697eaf0aca3a3aea3a75164746ffaa79",
                true
            ),
            (
                "0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c",
                "Test With Truncation",
                "56461ef2342edc00f9bab995690efd4c",
                false
            ),
            (
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "Test Using Larger Than Block-Size Key - Hash Key First",
                "6b1ab7fe4bd7bf8f0b62e6ce61b9d0cd",
                false
            ),
            (
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "Test Using Larger Than Block-Size Key and Larger Than One Block-Size Data",
                "6f630fad67cda0ee1fb1f562db3aa53e",
                false
            )
        ]
        
        for test in tests {
            if test.3 {
                let result = HMAC<MD5>.authenticate([UInt8](hexString: test.1), withKey: [UInt8](hexString: test.0)).hexString.lowercased()
                
                XCTAssertEqual(result, test.2.lowercased())
            } else {
                let result = HMAC<MD5>.authenticate(test.1.bytes, withKey: [UInt8](hexString: test.0)).hexString.lowercased()
                
                XCTAssertEqual(result, test.2.lowercased())
            }
        }
        
        // Source: https://github.com/krzyzanowskim/CryptoSwift/blob/swift3-snapshots/CryptoSwiftTests/HMACTests.swift
        XCTAssertEqual(HMAC<MD5>.authenticate([], withKey: []), [0x74,0xe6,0xf7,0x29,0x8a,0x9c,0x2d,0x16,0x89,0x35,0xf5,0x8c,0x00,0x1b,0xad,0x88])
    }
}*/
