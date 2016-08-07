import XCTest
@testable import MD5TestSuite
@testable import SHA1TestSuite
@testable import PBKDF2TestSuite

XCTMain([
    // MD5
    testCase(MD5Tests.allTests),

    // SHA1
    testCase(SHA1Tests.allTests),
    
    // PBKDF2
    testCase(PBKDF2Tests.allTests),
])
