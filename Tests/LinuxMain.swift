import XCTest
@testable import CryptoTests

XCTMain([
    testCase(CipherTests.allTests),
    testCase(HashTests.allTests),
    testCase(HMACTests.allTests),
])
