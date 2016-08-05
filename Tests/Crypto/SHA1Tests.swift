import XCTest
import Core
import SHA1
import HMAC
import PBKDF2

class SHA1Tests: XCTestCase {
    func testSHA1() {
        // Source: https://en.wikipedia.org/wiki/SHA-1#Example_hashes
        let tests = [
            ("The quick brown fox jumps over the lazy dog", "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12"),
            ("The quick brown fox jumps over the lazy cog", "de9f2c7fd25e1b3afad3e85a0bd17d9b100db4b3"),
            ("", "da39a3ee5e6b4b0d3255bfef95601890afd80709"),
        ]
        
        for test in tests {
            let result = SHA1.hash(test.0.bytes).hexString.lowercased()
            XCTAssertEqual(result, test.1.lowercased())
        }
        
        // Source: https://github.com/krzyzanowskim/CryptoSwift/blob/swift3-snapshots/CryptoSwiftTests/HashTests.swift
        XCTAssertEqual(SHA1.hash([0x31, 0x32, 0x33]).hexString.lowercased(), "40bd001563085fc35165329ea1ff5c5ecbdbbeef")
    }
    
    func testStreamingSHA1performance() {
        let data = [UInt8](repeating: Byte.A, count: 50000000)
        
        let nonStreamingResult = SHA1.hash(data)
        var streamingResult: [UInt8]!
        
        measure {
            let SHA1stream = SHA1()
            
            for i in 0..<(data.count/1000) {
                SHA1stream.append(bytes: Array(data[i*1000..<(i+1)*1000]))
            }
            
            streamingResult = SHA1stream.complete()
        }
        
        XCTAssertEqual(nonStreamingResult, streamingResult)
    }
    
    func testBulkSHA1performance() {
        let data = [UInt8](repeating: Byte.A, count: 50000000)
        
        measure {
            _ = SHA1.hash(data)
        }
    }
    
    func testHMACSHA1() {
        // Source: https://github.com/bcgit/bc-java/blob/adecd89d33edf278a5c601af2de696f0a6f65251/core/src/test/java/org/bouncycastle/crypto/test/SHA1HMacTest.java
        let tests = [
            ("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b", "Hi There", "b617318655057264e28bc0b6fb378c8ef146be00", false),
            ("4a656665", "what do ya want for nothing?", "effcdf6ae5eb2fa2d27416d5f184df9c259a7c79", false),
            ("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd", "125d7342b9ac11cd91a39af48aa17b4f63f175d3", true),
            ("0102030405060708090a0b0c0d0e0f10111213141516171819", "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd", "4c9007f4026250c6bc8414f9bf50c86c2d7235da", true),
            ("0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c", "Test With Truncation", "4c1a03424b55e07fe7f27be1d58bb9324a9a5a04", false),
            ("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "Test Using Larger Than Block-Size Key - Hash Key First", "aa4ae5e15272d00e95705637ce8a3b55ed402112", false),
            ("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "Test Using Larger Than Block-Size Key and Larger Than One Block-Size Data", "e8e99d0f45237d786d6bbaa7965c7808bbff1a91", false)
        ]
        
        for test in tests {
            if test.3 {
                let result = HMAC<SHA1>.authenticate([UInt8](hexString: test.1), withKey: [UInt8](hexString: test.0)).hexString.lowercased()
                
                XCTAssertEqual(result, test.2.lowercased())
            } else {
                let result = HMAC<SHA1>.authenticate(test.1.bytes, withKey: [UInt8](hexString: test.0)).hexString.lowercased()
                
                XCTAssertEqual(result, test.2.lowercased())
            }
        }
        
        // Source: https://github.com/krzyzanowskim/CryptoSwift/blob/swift3-snapshots/Sources/CryptoSwift/HMAC.swift
        XCTAssertEqual(HMAC<SHA1>.authenticate([], withKey: []), [0x74,0xe6,0xf7,0x29,0x8a,0x9c,0x2d,0x16,0x89,0x35,0xf5,0x8c,0x00,0x1b,0xad,0x88])
    }
    
    func testPBKDF2withSHA1() throws {
        // Source: `php $(PROJECT_DIR)/PHP/produce_tests.php`
        let tests = [
            ("password", "salt", "6e88be8bad7eae9d9e10aa061224034fed48d03f"),
            ("password2", "othersalt", "7a0363dd39e51c2cf86218038ad55f6fbbff6291"),
            ("somewhatlongpasswordstringthatIwanttotest", "1", "8cba8dd99a165833c8d7e3530641c0ecddc6e48c"),
            ("p", "somewhatlongsaltstringthatIwanttotest", "31593b82b859877ea36dc474503d073e6d56a33d")
            ]
        
        for test in tests {
            let result = try PBKDF2<SHA1>.derive(fromKey: test.0.bytes, usingSalt: test.1.bytes, iterating: 1000)
            
            XCTAssertEqual(result.hexString.lowercased(), test.2.lowercased())
        }
    }
    
    static var allTests : [(String, (SHA1Tests) -> () throws -> Void)] {
        return [
            ("testSHA1", testSHA1),
            ("testHMACSHA1", testHMACSHA1),
            ("testPBKDF2withSHA1", testPBKDF2withSHA1),
            ("testStreamingSHA1performance", testStreamingSHA1performance),
            ("testBulkSHA1performance", testBulkSHA1performance),
        ]
    }
}
