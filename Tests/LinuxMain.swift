import XCTest
@testable import MD5Tests
@testable import SHA1Tests
@testable import PBKDF2Tests

XCTMain([
    // MD5
    testCase(MD5Tests.allTests),

    // SHA1
    testCase(SHA1Tests.allTests),
    
    // PBKDF2
    testCase(PBKDF2Tests.allTests),
])
