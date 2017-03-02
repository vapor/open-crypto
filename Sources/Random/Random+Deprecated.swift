import Core

// MARK: Deprecated non-throwing properties
extension Random {
    /// Get a random Int8
    @available(*, deprecated, message: "Use the throwing method instead.")
    public var int8: Int8 {
        return try! makeInt8()
    }

    /// Get a random UInt8
    @available(*, deprecated, message: "Use the throwing method instead.")
    public var uint8: UInt8 {
        return try! makeUInt8()
    }

    /// Get a random Int16
    @available(*, deprecated, message: "Use the throwing method instead.")
    public var int16: Int16 {
        return try! makeInt16()
    }

    /// Get a random UInt16
    @available(*, deprecated, message: "Use the throwing method instead.")
    public var uint16: UInt16 {
        return try! makeUInt16()
    }

    /// Get a random Int32
    @available(*, deprecated, message: "Use the throwing method instead.")
    public var int32: Int32 {
        return try! makeInt32()
    }

    /// Get a random UInt32
    @available(*, deprecated, message: "Use the throwing method instead.")
    public var uint32: UInt32 {
        return try! makeUInt32()
    }

    /// Get a random Int64
    @available(*, deprecated, message: "Use the throwing method instead.")
    public var int64: Int64 {
        return try! makeInt64()
    }

    /// Get a random UInt64
    @available(*, deprecated, message: "Use the throwing method instead.")
    public var uint64: UInt64 {
        return try! makeUInt64()
    }

    /// Get a random Int
    @available(*, deprecated, message: "Use the throwing method instead.")
    public var int: Int {
        return try! makeInt()
    }

    /// Get a random UInt
    @available(*, deprecated, message: "Use the throwing method instead.")
    public var uint: UInt {
        return try! makeUInt()
    }
}

// MARK: - Deprecated non-throwing bytes method
extension Random {
    @available(*, deprecated, message: "Use the throwing method `bytes(count: Int)` instead.")
    public func bytes(_ num: Int) -> Bytes {
        return try! bytes(count: num)
    }
}

// MARK: - Deprecated static non-throwing methods/properties
extension Random where Self: EmptyInitializable {
    @available(*, deprecated, message: "Use the throwing method `bytes(count: Int)` instead.")
    public static func bytes(_ num: Int) -> Bytes {
        return try! bytes(count: num)
    }

    /// Get a random Int8
    @available(*, deprecated, message: "Use the throwing method `makeInt8()` instead.")
    public static var int8: Int8 {
        return try! makeInt8()
    }

    /// Get a random UInt8
    @available(*, deprecated, message: "Use the throwing method `makeUInt8()` instead.")
    public static var uint8: UInt8 {
        return try! makeUInt8()
    }

    /// Get a random Int16
    @available(*, deprecated, message: "Use the throwing method `makeInt16()` instead.")
    public static var int16: Int16 {
        return try! makeInt16()
    }

    /// Get a random UInt16
    @available(*, deprecated, message: "Use the throwing method `makeUInt16()` instead.")
    public static var uint16: UInt16 {
        return try! makeUInt16()
    }

    /// Get a random Int32
    @available(*, deprecated, message: "Use the throwing method `makeInt32()` instead.")
    public static var int32: Int32 {
        return try! makeInt32()
    }

    /// Get a random UInt32
    @available(*, deprecated, message: "Use the throwing method `makeUInt32()` instead.")
    public static var uint32: UInt32 {
        return try! makeUInt32()
    }

    /// Get a random Int64
    @available(*, deprecated, message: "Use the throwing method `makeInt64()` instead.")
    public static var int64: Int64 {
        return try! makeInt64()
    }

    /// Get a random UInt64
    @available(*, deprecated, message: "Use the throwing method `makeUInt64()` instead.")
    public static var uint64: UInt64 {
        return try! makeUInt64()
    }

    /// Get a random Int
    @available(*, deprecated, message: "Use the throwing method `makeInt()` instead.")
    public static var int: Int {
        return try! makeInt()
    }

    /// Get a random UInt
    @available(*, deprecated, message: "Use the throwing method `makeUInt()` instead.")
    public static var uint: UInt {
        return try! makeUInt()
    }
}
