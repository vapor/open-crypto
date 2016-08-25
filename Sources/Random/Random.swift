import Core

public protocol Random {
    init()
    func bytes(_ num: Int) -> Bytes
}

extension Random {
    /// Get a random int8
    public var int8: Int8 {
        return Int8(bitPattern: uint8)
    }

    /// Get a random uint8
    public var uint8: UInt8 {
        return bytes(1)[0]
    }

    /// Get a random int16
    public var int16: Int16 {
        let random = bytes(2)
        return UnsafeMutableRawPointer(mutating: random)
            .assumingMemoryBound(to: Int16.self)
            .pointee
    }

    /// Get a random uint16
    public var uint16: UInt16 {
        return UInt16(bitPattern: int16)
    }

    /// Get a random int32
    public var int32: Int32 {
        let random = bytes(4)
        return UnsafeMutableRawPointer(mutating: random)
            .assumingMemoryBound(to: Int32.self)
            .pointee
    }

    /// Get a random uint32
    public var uint32: UInt32 {
        return UInt32(bitPattern: int32)
    }

    /// Get a random int64
    public var int64: Int64 {
        let random = bytes(8)
        return UnsafeMutableRawPointer(mutating: random)
            .assumingMemoryBound(to: Int64.self)
            .pointee
    }

    /// Get a random uint64
    public var uint64: UInt64 {
        return UInt64(bitPattern: int64)
    }

    /// Get a random int
    public var int: Int {
        let random = bytes(MemoryLayout<Int>.size)
        return UnsafeMutableRawPointer(mutating: random)
            .assumingMemoryBound(to: Int.self)
            .pointee
    }

    /// Get a random uint
    public var uint: UInt {
        return UInt(bitPattern: int)
    }
}

// MARK: Static

extension Random {
    /// Get a random int8
    public static var int8: Int8 {
        return Self().int8
    }

    /// Get a random uint8
    public static var uint8: UInt8 {
        return Self().uint8
    }

    /// Get a random int16
    public static var int16: Int16 {
        return Self().int16
    }

    /// Get a random uint16
    public static var uint16: UInt16 {
        return Self().uint16
    }

    /// Get a random int32
    public static var int32: Int32 {
        return Self().int32
    }

    /// Get a random uint32
    public static var uint32: UInt32 {
        return Self().uint32
    }

    /// Get a random int64
    public static var int64: Int64 {
        return Self().int64
    }

    /// Get a random uint64
    public static var uint64: UInt64 {
        return Self().uint64
    }

    /// Get a random int
    public static var int: Int {
        return Self().int
    }

    /// Get a random uint
    public static var uint: UInt {
        return Self().uint
    }

    public static func bytes(_ num: Int) -> Bytes {
        return Self().bytes(num)
    }
}
