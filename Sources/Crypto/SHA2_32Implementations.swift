public final class SHA256 : SHA2_32 {
    public static let littleEndian = false
    public static let digestSize = 32
    public static let chunkSize = 64
    
    public var remainder = UnsafeMutablePointer<UInt8>.allocate(capacity: 63)
    public var containedRemainder = 0
    public var totalLength: UInt64 = 0
    
    deinit {
        self.remainder.deallocate(capacity: 63)
    }
    
    public var hash: [UInt8] {
        var buffer = [UInt8]()
        buffer.reserveCapacity(32)
        
        func convert(_ int: UInt32) -> [UInt8] {
            let int = int.bigEndian
            return [
                UInt8(int & 0xff),
                UInt8((int >> 8) & 0xff),
                UInt8((int >> 16) & 0xff),
                UInt8((int >> 24) & 0xff)
            ]
        }
        
        buffer.append(contentsOf: convert(h0))
        buffer.append(contentsOf: convert(h1))
        buffer.append(contentsOf: convert(h2))
        buffer.append(contentsOf: convert(h3))
        buffer.append(contentsOf: convert(h4))
        buffer.append(contentsOf: convert(h5))
        buffer.append(contentsOf: convert(h6))
        buffer.append(contentsOf: convert(h7))
        
        return buffer
    }
    
    public init() {    }
    
    var h0: UInt32 = 0x6a09e667
    var h1: UInt32 = 0xbb67ae85
    var h2: UInt32 = 0x3c6ef372
    var h3: UInt32 = 0xa54ff53a
    var h4: UInt32 = 0x510e527f
    var h5: UInt32 = 0x9b05688c
    var h6: UInt32 = 0x1f83d9ab
    var h7: UInt32 = 0x5be0cd19
    
    public func reset() {
        h0 = 0x6a09e667
        h1 = 0xbb67ae85
        h2 = 0x3c6ef372
        h3 = 0xa54ff53a
        h4 = 0x510e527f
        h5 = 0x9b05688c
        h6 = 0x1f83d9ab
        h7 = 0x5be0cd19
    }
    
    var a: UInt32 = 0
    var b: UInt32 = 0
    var c: UInt32 = 0
    var d: UInt32 = 0
    var e: UInt32 = 0
    var f: UInt32 = 0
    var g: UInt32 = 0
    var h: UInt32 = 0
}

public final class SHA224 : SHA2_32 {
    public static let littleEndian = false
    public static let digestSize = 28
    public static let chunkSize = 64
    
    public var remainder = UnsafeMutablePointer<UInt8>.allocate(capacity: 63)
    public var containedRemainder = 0
    public var totalLength: UInt64 = 0
    
    deinit {
        self.remainder.deallocate(capacity: 63)
    }
    
    public func reset() {
        h0 = 0xc1059ed8
        h1 = 0x367cd507
        h2 = 0x3070dd17
        h3 = 0xf70e5939
        h4 = 0xffc00b31
        h5 = 0x68581511
        h6 = 0x64f98fa7
        h7 = 0xbefa4fa4
    }
    
    public var hash: [UInt8] {
        var buffer = [UInt8]()
        buffer.reserveCapacity(28)
        
        func convert(_ int: UInt32) -> [UInt8] {
            let int = int.bigEndian
            return [
                UInt8(int & 0xff),
                UInt8((int >> 8) & 0xff),
                UInt8((int >> 16) & 0xff),
                UInt8((int >> 24) & 0xff)
            ]
        }
        
        buffer.append(contentsOf: convert(h0))
        buffer.append(contentsOf: convert(h1))
        buffer.append(contentsOf: convert(h2))
        buffer.append(contentsOf: convert(h3))
        buffer.append(contentsOf: convert(h4))
        buffer.append(contentsOf: convert(h5))
        buffer.append(contentsOf: convert(h6))
        
        return buffer
    }
    
    public init() {    }
    
    var h0: UInt32 = 0xc1059ed8
    var h1: UInt32 = 0x367cd507
    var h2: UInt32 = 0x3070dd17
    var h3: UInt32 = 0xf70e5939
    var h4: UInt32 = 0xffc00b31
    var h5: UInt32 = 0x68581511
    var h6: UInt32 = 0x64f98fa7
    var h7: UInt32 = 0xbefa4fa4
    
    var a: UInt32 = 0
    var b: UInt32 = 0
    var c: UInt32 = 0
    var d: UInt32 = 0
    var e: UInt32 = 0
    var f: UInt32 = 0
    var g: UInt32 = 0
    var h: UInt32 = 0
}
