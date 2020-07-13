⚠️ This library has been deprecated in favor of https://github.com/apple/swift-crypto

---

<p align="center">
    <img src="https://user-images.githubusercontent.com/1342803/59882676-e5ae1980-9380-11e9-8e61-c4eab4d531a8.png" alt="CryptoKit">
    <br>
    <br>
    <a href="https://developer.apple.com/documentation/cryptokit">
        <img src="http://img.shields.io/badge/api-docs-2196f3.svg" alt="API Docs">
    </a>
    <a href="https://discord.gg/vapor">
        <img src="https://img.shields.io/discord/431917998102675485.svg" alt="Team Chat">
    </a>
    <a href="LICENSE">
        <img src="http://img.shields.io/badge/license-MIT-brightgreen.svg" alt="MIT License">
    </a>
    <a href="https://circleci.com/gh/vapor/open-crypto">
        <img src="https://circleci.com/gh/vapor/open-crypto.svg?style=shield" alt="Continuous Integration">
    </a>
    <a href="https://swift.org">
        <img src="http://img.shields.io/badge/swift-5-brightgreen.svg" alt="Swift 5">
    </a>
</p>

---

OpenCrypto is a drop-in replacement for Apple's [CryptoKit](https://developer.apple.com/documentation/cryptokit) built on OpenSSL. 

This package is meant for use on platforms where CryptoKit is not available, like Linux. Most features from CryptoKit are available, but some are still missing:

- ✅ MD5
- ✅ SHA1
- ✅ SHA2 (256, 384, 512)
- ✅ HMAC
- ✅ AES GCM (128, 192, 256)
- ✅ ChaChaPoly (1305)
- ❌ Curve25519
- ❌ NIST P (256, 384, 521)

