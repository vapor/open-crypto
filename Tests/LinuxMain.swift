import XCTest
@testable import CipherTests
@testable import HashTests
@testable import HMACTests
@testable import RandomTests

XCTMain([
    // Cipher
    testCase(CipherTests.allTests),

    // Hash 
    testCase(HashTests.allTests),
    
    // HMAC
    testCase(HMACTests.allTests),

    // Random
    testCase(RandomTests.allTests),
])
