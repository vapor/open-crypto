extension Digest {
    /// See `Digest.hash(_:)`
    @available(*, deprecated, renamed: "hash")
    public func digest(_ data: LosslessDataConvertible) throws -> Data {
        return try hash(data)
    }
}
