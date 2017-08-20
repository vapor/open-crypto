// swift-tools-version:4.0
import PackageDescription

let package = Package(
    name: "Crypto",
    products: [
        .library(name: "Crypto", targets: ["Crypto"]),
    ],
    targets: [
        .target(name: "Crypto"),
        .testTarget(name: "CryptoTests", dependencies: ["Crypto"]),
    ]
)
