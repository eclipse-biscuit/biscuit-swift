// swift-tools-version: 6.0
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription
import CompilerPluginSupport

let package = Package(
    name: "biscuit-swift",
    platforms: [
        .iOS(.v16),
        .macOS(.v13),
        .tvOS(.v16),
        .watchOS(.v9),
        .visionOS(.v1),
    ],
    products: [
        .library(name: "Biscuits", targets: ["Biscuits"]),
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-crypto.git", "1.0.0" ..< "4.0.0"),
        .package(url: "https://github.com/apple/swift-protobuf.git", from: "1.26.0"),
        .package(url: "https://github.com/apple/swift-docc-plugin", from: "1.0.0"),
    ],
    targets: [
        .target(
            name: "Biscuits",
            dependencies: [
                .product(name: "Crypto", package: "swift-crypto"),
                .product(name: "SwiftProtobuf", package: "swift-protobuf"),
            ],
        ),
        .testTarget(
            name: "BiscuitsTests",
            dependencies: ["Biscuits"],
            resources: [.copy("Resources")]
        ),
    ]
)
