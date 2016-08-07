import Core
import Foundation
import Essentials
import HMAC

public enum PBKDF2Error: Error {
    case cannotIterate(times: Int)
    case cannotDeriveFromKey(Bytes)
    case cannotDeriveFromSalt(Bytes)
    case keySizeTooBig(UInt)
}

public final class PBKDF2<Variant: Hash> {
    public init() { }

    /// Used to make the block number
    /// Credit to Marcin Krzyzanowski
    private static func integerBytes(blockNum block: UInt) -> Bytes {
        var bytes = Bytes(repeating: 0, count: 4)
        bytes[0] = Byte((block >> 24) & 0xFF)
        bytes[1] = Byte((block >> 16) & 0xFF)
        bytes[2] = Byte((block >> 8) & 0xFF)
        bytes[3] = Byte(block & 0xFF)
        return bytes
    }
    
    public static func derive(fromKey key: Bytes, usingSalt salt: Bytes, iterating iterations: Int, keyLength keySize: UInt? = nil) throws -> Bytes {
        
        let keySize = keySize ?? UInt(Variant.blockSize)
        
        guard iterations > 0 else {
            throw PBKDF2Error.cannotIterate(times: 0)
        }
        
        guard key.count > 0 else {
            throw PBKDF2Error.cannotDeriveFromKey(key)
        }
        
        guard salt.count > 0 else {
            throw PBKDF2Error.cannotDeriveFromSalt(salt)
        }
        
        guard keySize <= UInt(((pow(2,32) as Double) - 1) * Double(Variant.blockSize)) else {
            throw PBKDF2Error.keySizeTooBig(keySize)
        }
        
        let blocks = UInt(ceil(Double(keySize) / Double(Variant.blockSize)))
        var response = Bytes()
        
        for block in 1...blocks {
            var s = salt
            s.append(contentsOf: self.integerBytes(blockNum: block))
            
            var ui = try HMAC<Variant>().authenticate(s, key: key)
            var u1 = ui
            
            for _ in 0..<iterations - 1 {
                u1 = try HMAC<Variant>().authenticate(u1, key: key)
                ui = xor(ui, u1)
            }
            
            response.append(contentsOf: ui)
        }
        
        return response
    }
    
    public static func validate(key: Bytes, usingSalt salt: Bytes, against: Bytes, iterating iterations: Int) throws -> Bool {
        let newHash = try derive(fromKey: key, usingSalt: salt, iterating: iterations, keyLength: UInt(against.count))
        
        return newHash == against
    }
}
