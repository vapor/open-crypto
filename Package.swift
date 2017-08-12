// swift-tools-version:4.0
import PackageDescription

let package = Package(
    name: "Crypto",
    products: [
        .library(name: "Crypto", targets: ["Crypto"]),
    ],
    dependencies: [
        // Core types and helpers.
        .package(url: "https://github.com/vapor/core.git", .branch("beta")),

        // Module for generating random bytes and numbers.
        .package(url: "https://github.com/vapor/random.git", .branch("beta")),

        // LibreSSL / OpenSSL module map for Swift.
        .package(url: "https://github.com/vapor/ctls.git", .upToNextMajor(from: "1.1.0")),
    ],
    targets: [
        .target(name: "Crypto", dependencies: ["Core", "Random"]),
        .testTarget(name: "CryptoTests", dependencies: ["Crypto"]),
    ]
)
