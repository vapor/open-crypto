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
        .package(url: "https://github.com/vapor/core.git", .branch("nio")),
    ],
    targets: [
        .testTarget(name: "CryptoTests", dependencies: ["Crypto"]),
        .target(name: "Random", dependencies: ["Bits"]),
        .testTarget(name: "RandomTests", dependencies: ["Random"]),
    ]
)

#if os(macOS)
package.targets.append(.target(name: "Crypto", dependencies: ["Async", "Bits", "COperatingSystem", "Debugging"]))
#else
package.dependencies.append(.package(url: "https://github.com/vapor/copenssl.git", from: "1.0.0-rc"))
package.targets.append(.target(name: "Crypto", dependencies: ["Async", "Bits", "COperatingSystem", "COpenSSL", "Debugging"]))
#endif
