import Core

public protocol Random {
    /// Get a random array of Bytes
    func bytes(count: Int) throws -> Bytes
}

public protocol EmptyInitializable {
    init()
}


// MARK: - Throwing getter methods
extension Random {
    /// Get a random Int8
    public func makeInt8() throws -> Int8 {
        return Int8(bitPattern: try makeUInt8())
    }

    /// Get a random UInt8
    public func makeUInt8() throws -> UInt8 {
        return try bytes(count: 1)[0]
    }

    /// Get a random Int16
    public func makeInt16() throws -> Int16 {
        return Int16(bitPattern: try makeUInt16())
    }

    /// Get a random UInt16
    public func makeUInt16() throws -> UInt16 {
        let random = try bytes(count: 2)
        return UnsafeRawPointer(random)
            .assumingMemoryBound(to: UInt16.self)
            .pointee
    }

    /// Get a random Int32
    public func makeInt32() throws -> Int32 {
        return Int32(bitPattern: try makeUInt32())
    }

    /// Get a random UInt32
    public func makeUInt32() throws -> UInt32 {
        let random = try bytes(count: 4)
        return UnsafeRawPointer(random)
            .assumingMemoryBound(to: UInt32.self)
            .pointee
    }

    /// Get a random Int64
    public func makeInt64() throws -> Int64 {
        return Int64(bitPattern: try makeUInt64())
    }

    /// Get a random UInt64
    public func makeUInt64() throws -> UInt64 {
        let random = try bytes(count: 8)
        return UnsafeRawPointer(random)
            .assumingMemoryBound(to: UInt64.self)
            .pointee
    }

    /// Get a random Int
    public func makeInt() throws -> Int {
        return Int(bitPattern: try makeUInt())
    }

    /// Get a random UInt
    public func makeUInt() throws -> UInt {
        let random = try bytes(count: MemoryLayout<UInt>.size)
        return UnsafeRawPointer(random)
            .assumingMemoryBound(to: UInt.self)
            .pointee
    }
}


// MARK: - Throwing static methods
extension Random where Self: EmptyInitializable {
    public static func bytes(count: Int) throws -> Bytes {
        return try Self().bytes(count: count)
    }

    /// Get a random Int8
    public static func makeInt8() throws -> Int8 {
        return try Self().makeInt8()
    }

    /// Get a random UInt8
    public static func makeUInt8() throws -> UInt8 {
        return try Self().makeUInt8()
    }

    /// Get a random Int16
    public static func makeInt16() throws -> Int16 {
        return try Self().makeInt16()
    }

    /// Get a random UInt16
    public static func makeUInt16() throws -> UInt16 {
        return try Self().makeUInt16()
    }

    /// Get a random Int32
    public static func makeInt32() throws -> Int32 {
        return try Self().makeInt32()
    }

    /// Get a random UInt32
    public static func makeUInt32() throws -> UInt32 {
        return try Self().makeUInt32()
    }

    /// Get a random Int64
    public static func makeInt64() throws -> Int64 {
        return try Self().makeInt64()
    }

    /// Get a random UInt64
    public static func makeUInt64() throws -> UInt64 {
        return try Self().makeUInt64()
    }

    /// Get a random Int
    public static func makeInt() throws -> Int {
        return try Self().makeInt()
    }

    /// Get a random UInt
    public static func makeUInt() throws -> UInt {
        return try Self().makeUInt()
    }
}
