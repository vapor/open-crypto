import Foundation

extension Swift.Collection where Iterator.Element == UInt8, IndexDistance == Int {
    /// The 12 bytes represented as 24-character hex-string
    public var hexString: String {
        var bytes = [UInt8]()
        bytes.reserveCapacity(self.count * 2)
        
        for byte in self {
            bytes.append(radix16table[Int(byte / 16)])
            bytes.append(radix16table[Int(byte % 16)])
        }
        
        return String(bytes: bytes, encoding: .utf8)!
    }
}

fileprivate let radix16table: [UInt8] = [0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66]

extension UnsafeMutableBufferPointer where Element == UInt8 {
    public func dealloc() {
        self.baseAddress?.deinitialize(count: self.count)
        self.baseAddress?.deallocate(capacity: self.count)
    }
    
    public func string() -> String? {
        return String(bytes: self, encoding: .utf8)
    }
}
