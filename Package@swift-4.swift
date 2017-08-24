// swift-tools-version:4.0
import PackageDescription

let package = Package(
    name: "Crypto",
    products: [
        .library(name: "Crypto", targets: ["Crypto"]),
    ],
    dependencies: [
        // Core extensions, type-aliases, and functions that facilitate common tasks.
        .package(url: "https://github.com/vapor/core.git", .revision("beta")),
    ],
    targets: [
        .target(name: "Crypto", dependencies: ["Core"]),
        .testTarget(name: "CryptoTests", dependencies: ["Crypto"]),
    ]
)
