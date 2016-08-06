//
//  Helpers.swift
//  Crypto
//
//  Created by Joannis Orlandos on 04/08/2016.
//
//

import Foundation
import Core

// Dirty hack because generics
public protocol ArrayProtocol: _ArrayProtocol {}
extension Array: ArrayProtocol {}

/// Provides access to hexStrings
///
/// TODO: Move to vapor/core
extension ArrayProtocol where Iterator.Element == Byte {
    public var hexString: String {
        #if os(Linux)
            return self.lazy.reduce("") { $0 + (NSString(format:"%02x", $1).description) }
        #else
            let s = self.lazy.reduce("") { $0 + String(format:"%02x", $1) }
            
            return s
        #endif
    }
    
    public init(hexString: String) {
        var data = Bytes()
        
        var gen = hexString.characters.makeIterator()
        while let c1 = gen.next(), let c2 = gen.next() {
            let s = String([c1, c2])
            
            guard let d = Byte(s, radix: 16) else {
                break
            }
            
            data.append(d)
        }
        
        self.init(data)
    }
}

extension Sequence where Iterator.Element == Byte {
    public func applyPadding(until length: Int) -> Bytes {
        var bytes = Array(self)
        if bytes.count == length {
            return bytes
        }

        bytes.append(0x80)

        while bytes.count < length {
            bytes.append(0x00)
        }

        return bytes
    }

    public func applyBitLength(of length: Int, reversed: Bool = true) -> Bytes {
        var lengthBytes = arrayOfBytes(length * 8, length: 8)

        if reversed {
            lengthBytes = lengthBytes.reversed()
        }

        return self + lengthBytes
    }
}
