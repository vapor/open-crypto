import Core

// MARK: Parser

extension Hash {
    public func verify(message: Bytes, matches input: Bytes) throws -> Bool {
        let parser = try Parser(input)
        let salt = try parser.parseSalt()
        let testDigest = self.digest(message: message, with: salt)
        return try testDigest == parser.parseDigest()
    }

    public func verify(message: BytesConvertible, matches digest: BytesConvertible) throws -> Bool {
        return try verify(
            message: message.makeBytes(),
            matches: digest.makeBytes()
        )
    }
}

// MARK: Serializer

extension Hash {
    public func make(message: Bytes, with salt: Salt) throws -> Bytes {
        let digest = self.digest(message: message, with: salt)
        let serializer = Serializer(salt, digest: digest)
        return serializer.serialize()
    }

    public func make(message: BytesConvertible, with salt: Salt) throws -> Bytes {
        return try make(
            message: message.makeBytes(),
            with: salt
        )
    }
}
