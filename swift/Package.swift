// swift-tools-version:5.7
import PackageDescription

let package = Package(
    name: "AuthMicroservice",
    platforms: [
        .macOS(.v12)
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-nio.git", from: "2.39.0"),
        .package(url: "https://github.com/apple/swift-crypto.git", from: "2.0.0")
    ],
    targets: [
        .executableTarget(
            name: "AuthMicroservice",
            dependencies: [
                .product(name: "NIO", package: "swift-nio"),
                .product(name: "NIOHTTP1", package: "swift-nio"),
                .product(name: "Crypto", package: "swift-crypto")
            ]
        )
    ]
)
