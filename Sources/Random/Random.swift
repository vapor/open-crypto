import Core

public protocol Random {
    init()

    @available(*, deprecated, message: "Use the throwing method instead.")
    func bytes(_ num: Int) -> Bytes

    /// Get a random array of Bytes
    func bytes(count: Int) throws -> Bytes
}


// MARK: - Deprecated non-throwing bytes method
extension Random {
    public func bytes(_ num: Int) -> Bytes {
        return try! bytes(count: num)
    }
}


// MARK: - Throwing getter methods
extension Random {
    /// Get a random Int8
    public func randInt8() throws -> Int8 {
        return Int8(bitPattern: try randUInt8())
    }

    /// Get a random UInt8
    public func randUInt8() throws -> UInt8 {
        return try bytes(count: 1)[0]
    }

    /// Get a random Int16
    public func randInt16() throws -> Int16 {
        return Int16(bitPattern: try randUInt16())
    }

    /// Get a random UInt16
    public func randUInt16() throws -> UInt16 {
        let random = try bytes(count: 2)
        return UnsafeRawPointer(random)
            .assumingMemoryBound(to: UInt16.self)
            .pointee
    }

    /// Get a random Int32
    public func randInt32() throws -> Int32 {
        return Int32(bitPattern: try randUInt32())
    }

    /// Get a random UInt32
    public func randUInt32() throws -> UInt32 {
        let random = try bytes(count: 4)
        return UnsafeRawPointer(random)
            .assumingMemoryBound(to: UInt32.self)
            .pointee
    }

    /// Get a random Int64
    public func randInt64() throws -> Int64 {
        return Int64(bitPattern: try randUInt64())
    }

    /// Get a random UInt64
    public func randUInt64() throws -> UInt64 {
        let random = try bytes(count: 8)
        return UnsafeRawPointer(random)
            .assumingMemoryBound(to: UInt64.self)
            .pointee
    }

    /// Get a random Int
    public func randInt() throws -> Int {
        return Int(bitPattern: try randUInt())
    }

    /// Get a random UInt
    public func randUInt() throws -> UInt {
        let random = try bytes(count: MemoryLayout<UInt>.size)
        return UnsafeRawPointer(random)
            .assumingMemoryBound(to: UInt.self)
            .pointee
    }
}


// MARK: - Throwing static methods
extension Random {
    public static func bytes(count: Int) throws -> Bytes {
        return try Self().bytes(count: count)
    }

    /// Get a random Int8
    public static func randInt8() throws -> Int8 {
        return try Self().randInt8()
    }

    /// Get a random UInt8
    public static func randUInt8() throws -> UInt8 {
        return try Self().randUInt8()
    }

    /// Get a random Int16
    public static func randInt16() throws -> Int16 {
        return try Self().randInt16()
    }

    /// Get a random UInt16
    public static func randUInt16() throws -> UInt16 {
        return try Self().randUInt16()
    }

    /// Get a random Int32
    public static func randInt32() throws -> Int32 {
        return try Self().randInt32()
    }

    /// Get a random UInt32
    public static func randUInt32() throws -> UInt32 {
        return try Self().randUInt32()
    }

    /// Get a random Int64
    public static func randInt64() throws -> Int64 {
        return try Self().randInt64()
    }

    /// Get a random UInt64
    public static func randUInt64() throws -> UInt64 {
        return try Self().randUInt64()
    }

    /// Get a random Int
    public static func randInt() throws -> Int {
        return try Self().randInt()
    }

    /// Get a random UInt
    public static func randUInt() throws -> UInt {
        return try Self().randUInt()
    }
}
