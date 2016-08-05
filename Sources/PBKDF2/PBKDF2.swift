import Core
import Foundation
import Essentials
import HMAC

public enum PBKDF2Error: Error {
    case invalidInput
}

public final class PBKDF2<Variant: Hash> {
    /// Used to make the block number
    /// Credit to Marcin Krzyzanowski
    private static func blockNumSaltThing(blockNum block: UInt) -> Bytes {
        var inti = Bytes(repeating: 0, count: 4)
        inti[0] = Byte((block >> 24) & 0xFF)
        inti[1] = Byte((block >> 16) & 0xFF)
        inti[2] = Byte((block >> 8) & 0xFF)
        inti[3] = Byte(block & 0xFF)
        return inti
    }
    
    public static func derive(fromKey password: Bytes, usingSalt salt: Bytes, iterating iterations: Int, keyLength keySize: Int? = nil) throws -> Bytes {
        let keySize = keySize ?? Variant.blockSize
        guard iterations > 0 && password.count > 0 && salt.count > 0 && keySize <= Int(((pow(2,32) as Double) - 1) * Double(Variant.blockSize)) else {
            throw PBKDF2Error.invalidInput
        }
        
        let blocks = UInt(ceil(Double(keySize) / Double(Variant.blockSize)))
        var response = Bytes()
        
        for block in 1...blocks {
            var s = salt
            s.append(contentsOf: self.blockNumSaltThing(blockNum: block))
            
            var ui = HMAC<Variant>.authenticate(s, withKey: password)
            var u1 = ui
            
            for _ in 0..<iterations - 1 {
                u1 = HMAC<Variant>.authenticate(u1, withKey: password)
                ui = xor(ui, u1)
            }
            
            response.append(contentsOf: ui)
        }
        
        return response
    }
}
