import XCTest
@testable import CryptoKit

class RandomTests: XCTestCase {
    func testURandom() throws {
        let rand = try URandom().generate(Int8.self)
        print(rand)
    }

    func testOSRandom() throws {
        let rand = try OSRandom().generate(Int64.self)
        print(rand)
        let bytes = OSRandom().generateData(count: 32)
        print(String(bytes: bytes, encoding: .utf8) ?? "n/a")
    }

    func testURandomCount() throws {
        let rand = try URandom().generateData(count: 65_536)
        XCTAssertEqual(rand.count, 65_536)
    }

    func testForTrailingZeros() throws {
        let rand = try URandom().generateData(count: 65_536)
        let tail = [UInt8](rand.suffix(8))
        let zeros = [UInt8](repeating: 0, count: 8)
        XCTAssertNotEqual(tail, zeros)
    }
    
    func testSwiftRandom() {
        let random = [UInt8].random(count: 1024)
        XCTAssertEqual(random.count, 1024)
    }
    
    
    static var allTests = [
        ("testURandom", testURandom),
        ("testOSRandom", testOSRandom),
        ("testURandomCount", testURandomCount),
        ("testForTrailingZeros", testForTrailingZeros),
        ("testSwiftRandom", testSwiftRandom),
    ]
}
