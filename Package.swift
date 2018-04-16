// swift-tools-version:4.0
import PackageDescription

let package = Package(
    name: "Crypto",
    products: [
        .library(name: "Crypto", targets: ["Crypto", "libbcrypt"]),
        .library(name: "Random", targets: ["Random"]),
    ],
    dependencies: [
        // 🌎 Utility package containing tools for byte manipulation, Codable, OS APIs, and debugging.
        .package(url: "https://github.com/vapor/core.git", from: "3.0.0"),

        /// Bindings to OpenSSL-compatible libraries for TLS support in SwiftNIO
        .package(url: "https://github.com/apple/swift-nio-ssl.git", from: "1.0.0"),
    ],
    targets: [
    	.target(name: "libbcrypt"),
        .target(name: "Crypto", dependencies: ["Async", "Bits", "Core", "COperatingSystem", "Debugging", "NIOOpenSSL", "Random", "libbcrypt"]),
        .testTarget(name: "CryptoTests", dependencies: ["Crypto"]),
        .target(name: "Random", dependencies: ["Bits"]),
        .testTarget(name: "RandomTests", dependencies: ["Random"]),
    ]
)
