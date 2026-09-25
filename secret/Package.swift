// swift-tools-version: 5.9
import PackageDescription

#if os(macOS)
let supportedPlatforms: [SupportedPlatform] = [.macOS(.v14)]
#else
let supportedPlatforms: [SupportedPlatform] = []
#endif

let package = Package(
    name: "secret",
    platforms: supportedPlatforms,
    targets: [
        .executableTarget(name: "secret")
    ]
)
