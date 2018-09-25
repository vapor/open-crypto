// swift-tools-version:4.0
import PackageDescription

let package = Package(
    name: "Crypto",
    products: [
        .library(name: "Crypto", targets: ["Crypto"]),
        .library(name: "Random", targets: ["Random"]),
    ],
    dependencies: [
        // 🌎 Utility package containing tools for byte manipulation, Codable, OS APIs, and debugging.
        .package(url: "https://github.com/vapor/core.git", from: "3.0.0"),

        /// Bindings to OpenSSL-compatible libraries for TLS support in SwiftNIO
        .package(url: "https://github.com/apple/swift-nio-ssl.git", from: "1.0.0"),
        
        /// Links OpenSSL / LibreSSL to SPM.
        .package(url: "https://github.com/apple/swift-nio-ssl-support.git", from: "1.0.0"),
    ],
    targets: [
        .target(name: "CBase32"),
        .target(name: "CBcrypt"),
        .target(name: "CCryptoOpenSSL"),
        .target(name: "Crypto", dependencies: [
            "Async",
            "Bits",
            "CBase32",
            "CBcrypt",
            "CCryptoOpenSSL",
            "Core",
            "COperatingSystem",
            "Debugging",
            "NIOOpenSSL",
            "Random"
        ]),
        .testTarget(name: "CryptoTests", dependencies: ["Crypto"]),
        .target(name: "Random", dependencies: ["Bits"]),
        .testTarget(name: "RandomTests", dependencies: ["Random"]),
    ]
)
