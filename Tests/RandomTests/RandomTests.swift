import XCTest
import Bits
@testable import Random

class RandomTests: XCTestCase {
    static var allTests = [
        ("testURandom", testURandom),
        ("testOSRandom", testOSRandom),
        ("testURandomCount", testURandomCount),
        ("testForTrailingZeros", testForTrailingZeros)
    ]

    func testURandom() throws {
        let rand = try URandom().generate(Int8.self)
        print(rand)
    }

    func testOSRandom() throws {
        let rand = try OSRandom().generate(Int64.self)
        print(rand)
        let bytes = OSRandom().generateData(count: 32)
        print(String(data: bytes, encoding: .utf8) ?? "n/a")
    }

    func testURandomCount() throws {
        let rand = try URandom().generateData(count: 65_536)
        XCTAssertEqual(rand.count, 65_536)
    }

    func testForTrailingZeros() throws {
        let rand = try URandom().generateData(count: 65_536)
        let tail = Bytes(rand.suffix(8))
        let zeros = Bytes(repeating: 0, count: 8)
        XCTAssertNotEqual(tail, zeros)
    }
    
    func testArray() throws {
        let array = [1, 2, 3]
        var results: [Int: Int] = [:]
        for _ in 0..<65_536 {
            if let foo = array.random {
                results[foo] = (results[foo] ?? 0) + 1
            }
        }
        print(results)
    }
    
    func testArrayRandomized() throws {
        let original = [4, 3, 5, 2, -1]
        var random1 = original
        var random2 = original
        while random1 == original || random2 == original || random1 == random2 {
            random1 = original.randomized()
            random2 = original.randomized()
        }
        XCTAssertNotEqual(original, random1)
        XCTAssertNotEqual(original, random2)
        XCTAssertNotEqual(random1, random2)
        XCTAssertEqual(original.sorted(by: <), random1.sorted(by: <))
        XCTAssertEqual(original.sorted(by: <), random2.sorted(by: <))
    }
}
