import Core

// MARK: Deprecated non-throwing properties
extension Random {
    /// Get a random Int8
    @available(*, deprecated, message: "Use the throwing method instead.")
    public var int8: Int8 {
        return try! randInt8()
    }

    /// Get a random UInt8
    @available(*, deprecated, message: "Use the throwing method instead.")
    public var uint8: UInt8 {
        return try! randUInt8()
    }

    /// Get a random Int16
    @available(*, deprecated, message: "Use the throwing method instead.")
    public var int16: Int16 {
        return try! randInt16()
    }

    /// Get a random UInt16
    @available(*, deprecated, message: "Use the throwing method instead.")
    public var uint16: UInt16 {
        return try! randUInt16()
    }

    /// Get a random Int32
    @available(*, deprecated, message: "Use the throwing method instead.")
    public var int32: Int32 {
        return try! randInt32()
    }

    /// Get a random UInt32
    @available(*, deprecated, message: "Use the throwing method instead.")
    public var uint32: UInt32 {
        return try! randUInt32()
    }

    /// Get a random Int64
    @available(*, deprecated, message: "Use the throwing method instead.")
    public var int64: Int64 {
        return try! randInt64()
    }

    /// Get a random UInt64
    @available(*, deprecated, message: "Use the throwing method instead.")
    public var uint64: UInt64 {
        return try! randUInt64()
    }

    /// Get a random Int
    @available(*, deprecated, message: "Use the throwing method instead.")
    public var int: Int {
        return try! randInt()
    }

    /// Get a random UInt
    @available(*, deprecated, message: "Use the throwing method instead.")
    public var uint: UInt {
        return try! randUInt()
    }
}

// MARK: - Deprecated static non-throwing methods/properties
extension Random {
    @available(*, deprecated, message: "Use the throwing method instead.")
    public static func bytes(_ num: Int) -> Bytes {
        return try! bytes(count: num)
    }

    /// Get a random Int8
    @available(*, deprecated, message: "Use the throwing method instead.")
    public static var int8: Int8 {
        return try! randInt8()
    }

    /// Get a random UInt8
    @available(*, deprecated, message: "Use the throwing method instead.")
    public static var uint8: UInt8 {
        return try! randUInt8()
    }

    /// Get a random Int16
    @available(*, deprecated, message: "Use the throwing method instead.")
    public static var int16: Int16 {
        return try! randInt16()
    }

    /// Get a random UInt16
    @available(*, deprecated, message: "Use the throwing method instead.")
    public static var uint16: UInt16 {
        return try! randUInt16()
    }

    /// Get a random Int32
    @available(*, deprecated, message: "Use the throwing method instead.")
    public static var int32: Int32 {
        return try! randInt32()
    }

    /// Get a random UInt32
    @available(*, deprecated, message: "Use the throwing method instead.")
    public static var uint32: UInt32 {
        return try! randUInt32()
    }

    /// Get a random Int64
    @available(*, deprecated, message: "Use the throwing method instead.")
    public static var int64: Int64 {
        return try! randInt64()
    }

    /// Get a random UInt64
    @available(*, deprecated, message: "Use the throwing method instead.")
    public static var uint64: UInt64 {
        return try! randUInt64()
    }

    /// Get a random Int
    @available(*, deprecated, message: "Use the throwing method instead.")
    public static var int: Int {
        return try! randInt()
    }

    /// Get a random UInt
    @available(*, deprecated, message: "Use the throwing method instead.")
    public static var uint: UInt {
        return try! randUInt()
    }
}
