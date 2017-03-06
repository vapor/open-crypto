import Foundation
import Random
import Core

public final class Hash {
    static let random = URandom()

    private var p: UnsafeMutablePointer<UInt32>
    private var s: UnsafeMutablePointer<UInt32>

    init() {
        p = UnsafeMutablePointer<UInt32>
            .allocate(capacity: Key.p.count)
        p.initialize(
            from: UnsafeMutableRawPointer(mutating: Key.p)
                .assumingMemoryBound(to: UInt32.self),
            count: Key.p.count
        )

        s = UnsafeMutablePointer<UInt32>
            .allocate(capacity: Key.s.count)
        s.initialize(
            from: UnsafeMutableRawPointer(mutating: Key.s)
                .assumingMemoryBound(to: UInt32.self),
            count: Key.s.count
        )
    }

    deinit {
        p.deinitialize()
        p.deallocate(capacity: Key.p.count)

        s.deinitialize()
        s.deallocate(capacity: Key.s.count)
    }


    public func digest(message: Bytes, with salt: Salt) -> Bytes {
        let message = message + [0]
        
        var j: Int
        let clen: Int = 6
        var cdata: [UInt32] = Key.ctext
        enhanceKeySchedule(
            with: salt.bytes,
            key: message
        )

        let rounds = 1 << salt.cost

        for _ in 0..<rounds {
            key(message)
            key(salt.bytes)
        }

        for _ in 0..<64 {
            for j in 0..<(clen >> 1) {
                self.encipher(lr: &cdata, off: j << 1)
            }
        }

        var result = Bytes(repeating: 0, count: clen * 4)

        j = 0
        for i in 0..<clen {
            result[j] = UInt8(truncatingBitPattern: (cdata[i] >> 24) & 0xff)
            j += 1
            result[j] = UInt8(truncatingBitPattern: (cdata[i] >> 16) & 0xff)
            j += 1
            result[j] = UInt8(truncatingBitPattern: (cdata[i] >> 8) & 0xff)
            j += 1
            result[j] = UInt8(truncatingBitPattern: cdata[i] & 0xff)
            j += 1
        }

        return result[0..<23].array
    }

    private func streamToWord(
        with data: UnsafeMutablePointer<Byte>,
        length: Int,
        off offp: inout UInt32
    ) -> UInt32 {
        var _ : Int
        var word : UInt32 = 0
        var off  : UInt32 = offp

        for _ in 0..<4{
            word = (word << 8) | (UInt32(data[Int(off)]) & 0xff)
            off = (off + 1) % UInt32(length)
        }

        offp = off
        return word
    }

    private func encipher(lr: UnsafeMutablePointer<UInt32>, off: Int) {
        if off < 0 {
            // Invalid offset.
            return
        }

        var n : UInt32
        var l : UInt32 = lr[off]
        var r : UInt32 = lr[off + 1]

        l ^= p[0]
        var i : Int = 0
        while i <= 16 - 2 {
            // Feistel substitution on left word
            n = s.advanced(by: Int((l >> 24) & 0xff)).pointee
            n = n &+ s.advanced(by: Int(0x100 | ((l >> 16) & 0xff))).pointee
            n ^= s.advanced(by: Int(0x200 | ((l >> 8) & 0xff))).pointee
            n = n &+ s.advanced(by: Int(0x300 | (l & 0xff))).pointee
            i += 1
            r ^= n ^ p.advanced(by: i).pointee

            // Feistel substitution on right word
            n = s.advanced(by: Int((r >> 24) & 0xff)).pointee
            n = n &+ s.advanced(by: Int(0x100 | ((r >> 16) & 0xff))).pointee
            n ^= s.advanced(by: Int(0x200 | ((r >> 8) & 0xff))).pointee
            n = n &+ s.advanced(by: Int(0x300 | (r & 0xff))).pointee
            i += 1
            l ^= n ^ p.advanced(by: i).pointee
        }

        lr[off] = r ^ p.advanced(by: 16 + 1).pointee
        lr[off + 1] = l
    }

    private func key(_ key: Bytes) {
        var koffp: UInt32 = 0
        var lr: [UInt32] = [0, 0]
        let plen: Int = 18
        let slen: Int = 1024

        let keyPointer : UnsafeMutablePointer<UInt8> = UnsafeMutablePointer<UInt8>(mutating: key)
        let keyLength : Int = key.count

        for i in 0..<plen {
            p[i] = p[i] ^ streamToWord(with: keyPointer, length: keyLength, off: &koffp)
        }

        var i = 0

        while i < plen {
            self.encipher(lr: &lr, off: 0)
            p[i] = lr[0]
            p[i + 1] = lr[1]
            i += 2
        }

        i = 0

        while i < slen {
            self.encipher(lr: &lr, off: 0)
            s[i] = lr[0]
            s[i + 1] = lr[1]
            i += 2
        }
    }

    private func enhanceKeySchedule(with data: [UInt8], key: [UInt8]) {
        var koffp: UInt32 = 0
        var doffp: UInt32 = 0

        var lr: [UInt32] = [0, 0]

        let keyPointer: UnsafeMutablePointer<UInt8> = UnsafeMutablePointer<UInt8>(mutating: key)
        let keyLength: Int = key.count
        let dataPointer: UnsafeMutablePointer<UInt8> = UnsafeMutablePointer<UInt8>(mutating: data)
        let dataLength: Int = data.count

        for i in 0..<Key.p.count {
            p[i] = p[i] ^ streamToWord(with: keyPointer, length: keyLength, off: &koffp)
        }

        var i = 0

        while i < Key.p.count {
            lr[0] ^= streamToWord(with: dataPointer, length: dataLength, off: &doffp)
            lr[1] ^= streamToWord(with: dataPointer, length: dataLength, off: &doffp)
            self.encipher(lr: &lr, off: 0)
            p[i] = lr[0]
            p[i + 1] = lr[1]

            i += 2
        }

        i = 0

        while i < Key.s.count {
            lr[0] ^= streamToWord(with: dataPointer, length: dataLength, off: &doffp)
            lr[1] ^= streamToWord(with: dataPointer, length: dataLength, off: &doffp)
            self.encipher(lr: &lr, off: 0)
            s[i] = lr[0]
            s[i + 1] = lr[1]

            i += 2
        }
    }
}
