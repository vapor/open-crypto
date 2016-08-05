// Originally based on CryptoSwift by Marcin Krzyżanowski <marcin.krzyzanowski@gmail.com>
// Copyright (C) 2014 Marcin Krzyżanowski <marcin.krzyzanowski@gmail.com>
// This software is provided 'as-is', without any express or implied warranty.
//
// In no event will the authors be held liable for any damages arising from the use of this software.
//
// Permission is granted to anyone to use this software for any purpose,including commercial applications, and to alter it and redistribute it freely, subject to the following restrictions:
//
// - The origin of this software must not be misrepresented; you must not claim that you wrote the original software. If you use this software in a product, an acknowledgment in the product documentation is required.
// - Altered source versions must be plainly marked as such, and must not be misrepresented as being the original software.
// - This notice may not be removed or altered from any source or binary distribution.

import Core

internal func arrayOfBytes<T>(_ value:T, length:Int? = nil) -> [UInt8] {
    let totalBytes = length ?? sizeof(T.self)
    
    let valuePointer = UnsafeMutablePointer<T>.allocate(capacity: 1)
    
    valuePointer.pointee = value
    
    let bytesPointer = UnsafeMutablePointer<UInt8>(valuePointer)
    var bytes = [UInt8](repeating: 0, count: totalBytes)
    for j in 0..<min(sizeof(T.self),totalBytes) {
        bytes[totalBytes - 1 - j] = (bytesPointer + j).pointee
    }
    
    valuePointer.deinitialize()
    valuePointer.deallocate(capacity: 1)
    
    return bytes
}

internal func toUInt32Array(_ slice: ArraySlice<UInt8>) -> Array<UInt32> {
    var result = Array<UInt32>()
    result.reserveCapacity(16)
    
    for idx in stride(from: slice.startIndex, to: slice.endIndex, by: sizeof(UInt32.self)) {
        let val1:UInt32 = (UInt32(slice[idx.advanced(by: 3)]) << 24)
        let val2:UInt32 = (UInt32(slice[idx.advanced(by: 2)]) << 16)
        let val3:UInt32 = (UInt32(slice[idx.advanced(by: 1)]) << 8)
        let val4:UInt32 = UInt32(slice[idx])
        let val:UInt32 = val1 | val2 | val3 | val4
        result.append(val)
    }
    return result
}

//internal func toUInt64Array(_ slice: ArraySlice<UInt8>) -> Array<UInt64> {
//    var result = Array<UInt64>()
//    result.reserveCapacity(32)
//    for idx in stride(from: slice.startIndex, to: slice.endIndex, by: sizeof(UInt64.self)) {
//        var val:UInt64 = 0
//        val |= UInt64(slice[idx.advanced(by: 7)]) << 56
//        val |= UInt64(slice[idx.advanced(by: 6)]) << 48
//        val |= UInt64(slice[idx.advanced(by: 5)]) << 40
//        val |= UInt64(slice[idx.advanced(by: 4)]) << 32
//        val |= UInt64(slice[idx.advanced(by: 3)]) << 24
//        val |= UInt64(slice[idx.advanced(by: 2)]) << 16
//        val |= UInt64(slice[idx.advanced(by: 1)]) << 8
//        val |= UInt64(slice[idx.advanced(by: 0)]) << 0
//        result.append(val)
//    }
//    return result
//}

internal func xor(_ lhs: [UInt8], _ rhs: [UInt8]) -> [UInt8] {
    var result = [UInt8](repeating: 0, count: min(lhs.count, rhs.count))
    
    for i in 0..<result.count {
        result[i] = lhs[i] ^ rhs[i]
    }
    
    return result
}

extension String {
    internal subscript (i: Int) -> Character {
        return self[index(self.startIndex, offsetBy: i)]
    }
    
    internal subscript (i: Int) -> String {
        return String(self[i] as Character)
    }
    
    internal subscript (r: Range<Int>) -> String {
        let r2 = Range.init(uncheckedBounds: (lower: index(startIndex, offsetBy: r.lowerBound), upper: index(startIndex, offsetBy: r.upperBound)))
        
        return substring(with: r2)
    }
}

extension Character {
    func utf16Value() -> UInt16 {
        for s in String(self).utf16 {
            return s
        }
        return 0
    }
}

// Too slow for actual usage
//internal protocol CryptoUnsignedInteger: UnsignedInteger {
//    static var byteLength: Int { get }
//    
//    init(byte: Byte)
//    
//    func shiftLeft(by: Int) -> Self
//}
//
//internal func toUnsignedArray<U: CryptoUnsignedInteger>(_ slice: BytesSlice) -> [U] {
//    var result = [U]()
//    result.reserveCapacity(16)
//    
//    for index in stride(from: slice.startIndex, to: slice.endIndex, by: sizeof(UInt32.self)) {
//        var buffer = [U]()
//        var i = U.byteLength - 1
//        
//        while i >= 0 {
//            buffer.append(U(byte: slice[index.advanced(by: i)]).shiftLeft(by: i * 8))
//            i -= 1
//        }
//        
//        var val = buffer.first!
//        buffer.removeFirst()
//        
//        for item in buffer {
//            val = val | item
//        }
//        
//        result.append(val)
//    }
//    
//    return result
//}
//
//extension UInt32: CryptoUnsignedInteger {
//    static var byteLength: Int = 4
//    
//    init(byte: Byte) {
//        self = UInt32.init(byte)
//    }
//    
//    func shiftLeft(by: Int) -> UInt32 {
//        let val: UInt32 = (self << UInt32(by))
//        return val
//    }
//}
//
//extension UInt64: CryptoUnsignedInteger {
//    static var byteLength: Int = 8
//    
//    init(byte: Byte) {
//        self = UInt64.init(byte)
//    }
//    
//    func shiftLeft(by: Int) -> UInt64 {
//        let val: UInt64 = (self << UInt64(by))
//        return val
//    }
//}
