import XCTest
@testable import HMACTests
@testable import MD5Tests
@testable import RandomTests
@testable import SHA1Tests
@testable import SHA2Tests

XCTMain([
	// HMAC
	testCase(HMACTests.allTests),

    // MD5
    testCase(MD5Tests.allTests),

    // Random
    testCase(RandomTests.allTests),

    // SHA1
    testCase(SHA1Tests.allTests),
    
    // SHA2
    testCase(SHA224Tests.allTests),
    testCase(SHA256Tests.allTests),
    testCase(SHA384Tests.allTests),
    testCase(SHA512Tests.allTests),
])
