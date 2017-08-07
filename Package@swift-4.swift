// swift-tools-version:4.0
import PackageDescription

let package = Package(
    name: "Crypto",
    products: [
        .library(name: "Crypto", targets: ["Crypto"]),
    ],
    dependencies: [
        // Module for generating random bytes and numbers.
        .package(url: "https://github.com/vapor/random.git", .upToNextMajor(from: "1.2.0")),

        // LibreSSL / OpenSSL module map for Swift.
        .package(url: "https://github.com/vapor/ctls.git", .upToNextMajor(from: "1.1.0")),
    ],
    targets: [
        .target(name: "Crypto", dependencies: ["Random"]),
    ]
)
