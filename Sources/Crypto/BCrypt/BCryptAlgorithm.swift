import Bits
import Foundation

/// Internal BCrypt implementation.
internal final class BCryptAlgorithm {
    // the salt for this hash
    public let config: BCryptConfig
    
    // keys
    private var p: UnsafeMutablePointer<UInt32>
    private var s: UnsafeMutablePointer<UInt32>
    
    public init(config: BCryptConfig) throws {
        p = UnsafeMutablePointer<UInt32>
            .allocate(capacity: BCryptKeys.p.count)
        p.initialize(
            from: UnsafeMutableRawPointer(mutating: BCryptKeys.p)
                .assumingMemoryBound(to: UInt32.self),
            count: BCryptKeys.p.count
        )
        
        s = UnsafeMutablePointer<UInt32>
            .allocate(capacity: BCryptKeys.s.count)
        s.initialize(
            from: UnsafeMutableRawPointer(mutating: BCryptKeys.s)
                .assumingMemoryBound(to: UInt32.self),
            count: BCryptKeys.s.count
        )

        self.config = config
        
        guard case .two(let scheme) = self.config.version else {
            throw CryptoError(identifier: "unsupportedBCryptVersion", reason: "BCrypt version \(config.version) is not supported.")
        }
        
        guard scheme == .a || scheme == .x || scheme == .y else {
            throw CryptoError(identifier: "unsupportedBCryptVersion", reason: "BCrypt version \(config.version) is not supported.")
        }
    }
    
    deinit {
        p.deinitialize(count: BCryptKeys.p.count)
        p.deallocate()
        
        s.deinitialize(count: BCryptKeys.s.count)
        s.deallocate()
    }
    
    func digest(message: Data) -> Data {
        var message = message + [0]
        
        var j: Int
        let clen: Int = 6
        var cdata: [UInt32] = BCryptKeys.ctext

        var saltData = config.salt
        enhanceKeySchedule(with: &saltData, key: &message)
        
        let rounds = 1 << config.cost
        
        for _ in 0..<rounds {
            key(&message)
            key(&saltData)
        }
        
        for _ in 0..<64 {
            for j in 0..<(clen >> 1) {
                self.encipher(lr: &cdata, off: j << 1)
            }
        }
        
        var result = Data(repeating: 0, count: clen &* 4)
        
        j = 0
        for i in 0..<clen {
            #if swift(>=4)
                result[j] = UInt8(truncatingIfNeeded: (cdata[i] >> 24) & 0xff)
                j += 1
                result[j] = UInt8(truncatingIfNeeded: (cdata[i] >> 16) & 0xff)
                j += 1
                result[j] = UInt8(truncatingIfNeeded: (cdata[i] >> 8) & 0xff)
                j += 1
                result[j] = UInt8(truncatingIfNeeded: cdata[i] & 0xff)
                j += 1
            #else
                result[j] = UInt8(truncatingBitPattern: (cdata[i] >> 24) & 0xff)
                j += 1
                result[j] = UInt8(truncatingBitPattern: (cdata[i] >> 16) & 0xff)
                j += 1
                result[j] = UInt8(truncatingBitPattern: (cdata[i] >> 8) & 0xff)
                j += 1
                result[j] = UInt8(truncatingBitPattern: cdata[i] & 0xff)
                j += 1
            #endif
        }
        
        return Data(result[0..<23])
    }
    
    // MARK: Private
    
    fileprivate func streamToWord(
        with data: UnsafeMutablePointer<Byte>,
        length: Int,
        off offp: inout UInt32
        ) -> UInt32 {
        var _ : Int
        var word : UInt32 = 0
        var off  : UInt32 = offp
        
        for _ in 0..<4{
            word = (word << 8) | (UInt32(data[Int(off)]) & 0xff)
            off = (off &+ 1) % UInt32(length)
        }
        
        offp = off
        return word
    }
    
    fileprivate func encipher(lr: UnsafeMutablePointer<UInt32>, off: Int) {
        if off < 0 {
            // Invalid offset.
            return
        }
        
        var n : UInt32
        var l : UInt32 = lr[off]
        var r : UInt32 = lr[off &+ 1]
        
        l ^= p[0]
        var i : Int = 0
        while i <= 16 &- 2 {
            // Feistel substitution on left word
            n = s.advanced(by: numericCast((l >> 24) & 0xff)).pointee
            n = n &+ s.advanced(by: numericCast(0x100 | ((l >> 16) & 0xff))).pointee
            n ^= s.advanced(by: numericCast(0x200 | ((l >> 8) & 0xff))).pointee
            n = n &+ s.advanced(by: numericCast(0x300 | (l & 0xff))).pointee
            i += 1
            r ^= n ^ p.advanced(by: i).pointee
            
            // Feistel substitution on right word
            n = s.advanced(by: numericCast((r >> 24) & 0xff)).pointee
            n = n &+ s.advanced(by: numericCast(0x100 | ((r >> 16) & 0xff))).pointee
            n ^= s.advanced(by: numericCast(0x200 | ((r >> 8) & 0xff))).pointee
            n = n &+ s.advanced(by: numericCast(0x300 | (r & 0xff))).pointee
            i += 1
            l ^= n ^ p.advanced(by: i).pointee
        }
        
        lr[off] = r ^ p.advanced(by: 16 &+ 1).pointee
        lr[off &+ 1] = l
    }
    
    fileprivate func key(_ key: inout Data) {
        var koffp: UInt32 = 0
        var lr: [UInt32] = [0, 0]
        let plen: Int = 18
        let slen: Int = 1024

        let keyLength = key.count
        key.withUnsafeMutableBytes { (keyPointer: MutableBytesPointer) in
            
            for i in 0..<plen {
                p[i] = p[i] ^ streamToWord(with: keyPointer, length: keyLength, off: &koffp)
            }
            
            var i = 0
            
            while i < plen {
                self.encipher(lr: &lr, off: 0)
                p[i] = lr[0]
                p[i &+ 1] = lr[1]
                i = i &+ 2
            }
            
            i = 0
            
            while i < slen {
                self.encipher(lr: &lr, off: 0)
                s[i] = lr[0]
                s[i &+ 1] = lr[1]
                i = i &+ 2
            }
        }
    }
    
    fileprivate func enhanceKeySchedule(with data: inout Data, key: inout Data) {
        var koffp: UInt32 = 0
        var doffp: UInt32 = 0
        
        var lr: [UInt32] = [0, 0]

        let keyLength: Int = key.count
        let dataLength: Int = data.count

        key.withUnsafeMutableBytes { (keyPointer: MutableBytesPointer) in
            data.withUnsafeMutableBytes { (dataPointer: MutableBytesPointer) in
                for i in 0..<BCryptKeys.p.count {
                    p[i] = p[i] ^ streamToWord(with: keyPointer, length: keyLength, off: &koffp)
                }
                
                var i = 0
                
                while i < BCryptKeys.p.count {
                    lr[0] ^= streamToWord(with: dataPointer, length: dataLength, off: &doffp)
                    lr[1] ^= streamToWord(with: dataPointer, length: dataLength, off: &doffp)
                    self.encipher(lr: &lr, off: 0)
                    p[i] = lr[0]
                    p[i &+ 1] = lr[1]
                    
                    i = i &+ 2
                }
                
                i = 0
                
                while i < BCryptKeys.s.count {
                    lr[0] ^= streamToWord(with: dataPointer, length: dataLength, off: &doffp)
                    lr[1] ^= streamToWord(with: dataPointer, length: dataLength, off: &doffp)
                    self.encipher(lr: &lr, off: 0)
                    s[i] = lr[0]
                    s[i &+ 1] = lr[1]
                    
                    i = i &+ 2
                }
            }
        }
    }
}
