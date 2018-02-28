// swift-tools-version:4.0
import PackageDescription

let package = Package(
    name: "Crypto",
    products: [
        .library(name: "Crypto", targets: ["Crypto"]),
        .library(name: "Pufferfish", targets: ["Pufferfish"]),
        .library(name: "Random", targets: ["Random"]),
    ],
    dependencies: [
        // ⏱ Promises and reactive-streams in Swift built for high-performance and scalability.
        .package(url: "https://github.com/vapor/async.git", from: "1.0.0-rc"),

        // 🌎 Utility package containing tools for byte manipulation, Codable, OS APIs, and debugging.
        .package(url: "https://github.com/vapor/core.git", from: "3.0.0-rc"),
    ],
    targets: [
        .testTarget(name: "CryptoTests", dependencies: ["Crypto"]),
        .target(name: "Pufferfish"),
        .testTarget(name: "PufferfishTests", dependencies: ["Pufferfish"]),
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
