import XCTest
import Core
@testable import SHA2

class SHA512Tests: XCTestCase {
    static var allTests = [
        ("testBasic", testBasic),
        ("testPerformance", testPerformance)
    ]

    func testBasic() throws {
        // Source: https://en.wikipedia.org/wiki/SHA-2
        let tests = [
            "The quick brown fox jumps over the lazy dog": "07e547d9586f6a73f73fbac0435ed76951218fb7d0c8d788a309d785436bbb642e93a252a954f23912547d1e8a3b5ed6e1bfd7097821233fa0538f3db854fee6",
            "The quick brown fox jumps over the lazy cog": "3eeee1d0e11733ef152a6c29503b3ae20c4f1f3cda4cb26f1bc1a41f91c7fe4ab3bd86494049e201c4bd5155f31ecb7a3c8606843c4cc8dfcab7da11c8ae5045",
            "": "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
        ]

        for (key, expected) in tests {
            let result = try SHA512.hash(key.bytes).hexString.lowercased()
            XCTAssertEqual(result, expected.lowercased())
        }
    }
    
    func testPerformance() {
        let data = Bytes(repeating: Byte.A, count: 10_000_000)

        // ~0.250 release
        measure {
            let hasher = SHA512(data)
            _ = try! hasher.hash()
        }
    }
}
