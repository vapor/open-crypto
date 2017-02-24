import XCTest
import Core
@testable import Random

class RandomTests: XCTestCase {
    static var allTests = [
        ("testURandom", testURandom),
        ("testCryptoRandom", testCryptoRandom),
        ("testPseudoRandom", testPseudoRandom),
        ("testRandomCount", testRandomCount),
        ("testForTrailingZeros", testForTrailingZeros),
    ]

    func testURandom() throws {
        let rand = try URandom.randInt8()
        print(rand)
    }

    func testCryptoRandom() throws {
        let rand = try CryptoRandom.randUInt32()
        print(rand)
    }

    func testPseudoRandom() throws {
        let rand = try PseudoRandom.randInt64()
        print(rand)
    }

    func testRandomCount() throws {
        let rand = try URandom.bytes(count: 65_536)
        XCTAssertEqual(rand.count, 65_536)
    }

    func testForTrailingZeros() throws {
        let rand = try URandom.bytes(count: 65_536)
        let tail = Bytes(rand.suffix(8))
        let zeros = Bytes(repeating: 0, count: 8)
        XCTAssertNotEqual(tail, zeros)
    }
}
