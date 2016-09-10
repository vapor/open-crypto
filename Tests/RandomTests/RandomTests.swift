import XCTest
import Core
@testable import Random
import Hash

class RandomTests: XCTestCase {
    static var allTests = [
        ("testURandom", testURandom),
        ("testCryptoRandom", testCryptoRandom),
        ("testPsuedoRandom", testPsuedoRandom),
    ]

    func testURandom() throws {
        let rand = URandom.int8
        print(rand)
    }

    func testCryptoRandom() throws {
        let rand = URandom.uint32
        print(rand)
    }

    func testPsuedoRandom() throws {
        let rand = URandom.int64
        print(rand)
    }

    func testRandomHash() throws {
        let hash = try Hash.random(.sha1)
        print(hash)
    }
}
