import XCTest
import Core
@testable import Hash

class HashTests: XCTestCase {
    static var allTests = [
        ("testSHA1", testSHA1),
        ("testSHA224", testSHA224),
        ("testSHA384", testSHA384),
    ]

    func testSHA1() throws {
        // Source: https://en.wikipedia.org/wiki/SHA-1#Example_hashes
        let tests = [
            "The quick brown fox jumps over the lazy dog": "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12",
            "The quick brown fox jumps over the lazy cog": "de9f2c7fd25e1b3afad3e85a0bd17d9b100db4b3",
            "": "da39a3ee5e6b4b0d3255bfef95601890afd80709"
        ]

        for (key, expected) in tests {
            let result = try Hash.make(.sha1, key.bytes).hexString.lowercased()
            XCTAssertEqual(result, expected.lowercased())
        }
    }

    func testWebSockets() throws {
        let message = "dGhlIHNhbXBsZSBub25jZQ==258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
        let expected: Bytes = [0xb3, 0x7a, 0x4f, 0x2c, 0xc0, 0x62, 0x4f, 0x16, 0x90, 0xf6,
            0x46, 0x06, 0xcf, 0x38, 0x59, 0x45, 0xb2, 0xbe, 0xc4, 0xea]

        let digest = try Hash.make(.sha1, message)
        XCTAssertEqual(expected, digest)
    }

    func testSHA224() throws {
        // Source: https://en.wikipedia.org/wiki/SHA-2
        let tests = [
            "The quick brown fox jumps over the lazy dog": "730e109bd7a8a32b1cb9d9a09aa2325d2430587ddbc0c38bad911525",
            "The quick brown fox jumps over the lazy cog": "fee755f44a55f20fb3362cdc3c493615b3cb574ed95ce610ee5b1e9b",
            "": "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f"
        ]

        for (key, expected) in tests {
            let result = try Hash.make(.sha224, key.bytes).hexString.lowercased()
            XCTAssertEqual(result, expected.lowercased())
        }
    }

    func testSHA256() throws {
        // Source: https://en.wikipedia.org/wiki/SHA-2
        let tests = [
            "The quick brown fox jumps over the lazy dog": "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592",
            "The quick brown fox jumps over the lazy cog": "e4c4d8f3bf76b692de791a173e05321150f7a345b46484fe427f6acc7ecc81be",
            "": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        ]

        for (key, expected) in tests {
            let result = try Hash.make(.sha256, key.bytes).hexString.lowercased()
            XCTAssertEqual(result, expected.lowercased())
        }
    }

    func testSHA384() throws {
        // Source: https://en.wikipedia.org/wiki/SHA-2
        let tests = [
            "The quick brown fox jumps over the lazy dog": "ca737f1014a48f4c0b6dd43cb177b0afd9e5169367544c494011e3317dbf9a509cb1e5dc1e85a941bbee3d7f2afbc9b1",
            "The quick brown fox jumps over the lazy cog": "098cea620b0978caa5f0befba6ddcf22764bea977e1c70b3483edfdf1de25f4b40d6cea3cadf00f809d422feb1f0161b",
            "": "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"
        ]

        for (key, expected) in tests {
            let result = try Hash.make(.sha384, key.bytes).hexString.lowercased()
            XCTAssertEqual(result, expected.lowercased())
        }
    }

    func testSHA512() throws {
        // Source: https://en.wikipedia.org/wiki/SHA-2
        let tests = [
            "The quick brown fox jumps over the lazy dog": "07e547d9586f6a73f73fbac0435ed76951218fb7d0c8d788a309d785436bbb642e93a252a954f23912547d1e8a3b5ed6e1bfd7097821233fa0538f3db854fee6",
            "The quick brown fox jumps over the lazy cog": "3eeee1d0e11733ef152a6c29503b3ae20c4f1f3cda4cb26f1bc1a41f91c7fe4ab3bd86494049e201c4bd5155f31ecb7a3c8606843c4cc8dfcab7da11c8ae5045",
            "": "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
        ]

        for (key, expected) in tests {
            let result = try Hash.make(.sha512, key.bytes).hexString.lowercased()
            XCTAssertEqual(result, expected.lowercased())
        }
    }

    func testMD5() throws {
        // Source: https://en.wikipedia.org/wiki/MD5#MD5_hashes
        let tests = [
            "The quick brown fox jumps over the lazy dog": "9e107d9d372bb6826bd81d3542a419d6",
            "The quick brown fox jumps over the lazy dog.": "e4d909c290d0fb1ca068ffaddf22cbd0",
            "": "d41d8cd98f00b204e9800998ecf8427e"
        ]

        for (key, expected) in tests {
            let result = try Hash.make(.md5, key.bytes).hexString.lowercased()
            XCTAssertEqual(result, expected.lowercased())
        }
    }

    func testRandom() throws {
        let hash = try Hash.random(.sha1)
        print(hash)
    }
}
