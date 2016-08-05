import Core

extension BCrypt {
    internal struct Base64 {
        /// BCrypt specific Base64 encoding table
        static let encodingTable : [Character] = [
            ".", "/", "A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K",
            "L", "M", "N", "O", "P", "Q", "R", "S", "T", "U", "V", "W", "X",
            "Y", "Z", "a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k",
            "l", "m", "n", "o", "p", "q", "r", "s", "t", "u", "v", "w", "x",
            "y", "z", "0", "1", "2", "3", "4", "5", "6", "7", "8", "9"
        ]
        
        /// BCrypt specific Base64 decoding table
        static let decodingTable : [Int8]  = [
            -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
            -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
            -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
            -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
            -1, -1, -1, -1, -1, -1,  0,  1, 54, 55,
            56, 57, 58, 59, 60, 61, 62, 63, -1, -1,
            -1, -1, -1, -1, -1,  2,  3,  4,  5,  6,
            7,  8,  9, 10, 11, 12, 13, 14, 15, 16,
            17, 18, 19, 20, 21, 22, 23, 24, 25, 26,
            27, -1, -1, -1, -1, -1, -1, 28, 29, 30,
            31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
            41, 42, 43, 44, 45, 46, 47, 48, 49, 50,
            51, 52, 53, -1, -1, -1, -1, -1
        ]
        
        /// Encodes the informtion specifically for BCrypt
        internal static func encode(data: [Int8], untilLength length: UInt) -> String {
            if data.count == 0 || length == 0 {
                return ""
            }
            
            var len : Int = Int(length)
            
            // If the length is too large, trim it to the data's length
            if len > data.count {
                len = data.count
            }
            
            var offset: Int = 0
            var c1: Byte
            var c2: Byte
            var result: String = String()
            
            var dataArray : Bytes = data.map {
                Byte(bitPattern: $0)
            }
            
            // Encode until we've reached the specified length
            while offset < len {
                c1 = dataArray[offset] & 0xff
                offset += 1
                result.append(encodingTable[Int((c1 >> 2) & 0x3f)])
                c1 = (c1 & 0x03) << 4
                if offset >= len {
                    result.append(encodingTable[Int(c1 & 0x3f)])
                    break
                }
                
                c2 = dataArray[offset] & 0xff
                offset += 1
                c1 |= (c2 >> 4) & 0x0f
                result.append(encodingTable[Int(c1 & 0x3f)])
                c1 = (c2 & 0x0f) << 2
                if offset >= len {
                    result.append(encodingTable[Int(c1 & 0x3f)])
                    break
                }
                
                c2 = dataArray[offset] & 0xff
                offset += 1
                c1 |= (c2 >> 6) & 0x03
                result.append(encodingTable[Int(c1 & 0x3f)])
                result.append(encodingTable[Int(c2 & 0x3f)])
            }
            
            return result
        }
        
        /// FInd the byte related to the character
        private static func char64of(x: Character) -> Int8 {
            let xAsInt : Int32 = Int32(x.utf16Value())
            
            if xAsInt < 0 || xAsInt > 128 - 1 {
                // The character would go out of bounds of the pre-calculated array so return -1.
                return -1
            }
            
            // Return the matching Base64 encoded character.
            return decodingTable[Int(xAsInt)]
        }
        
        /// Decodes the informtion specifically for BCrypt
        public static func decode(_ s: String, untilLength maxolen: UInt) -> [Int8] {
            let maxolen = Int(maxolen)
            
            var off : Int = 0
            var olen : Int = 0
            var result : [Int8] = [Int8](repeating: 0, count: maxolen)
            
            var c1 : Int8
            var c2 : Int8
            var c3 : Int8
            var c4 : Int8
            var o : Int8
            
            /// Calculate in blocks of 4 bytes
            /// Remain within the specified olen
            while off < s.characters.count - 1 && olen < maxolen {
                c1 = char64of(x: s[off])
                off += 1
                c2 = char64of(x: s[off])
                off += 1
                if c1 == -1 || c2 == -1 {
                    break
                }
                
                o = c1 << 2
                o |= (c2 & 0x30) >> 4
                result[olen] = o
                olen += 1
                if olen >= maxolen || off >= s.characters.count {
                    break
                }
                
                c3 = char64of(x: s[Int(off)])
                off += 1
                
                if c3 == -1 {
                    break
                }
                
                o = (c2 & 0x0f) << 4
                o |= (c3 & 0x3c) >> 2
                result[olen] = o
                olen += 1
                if olen >= maxolen || off >= s.characters.count {
                    break
                }
                
                c4 = char64of(x: s[off])
                off += 1
                o = (c3 & 0x03) << 6
                o |= c4
                result[olen] = o
                olen += 1
            }
            
            return Array(result[0..<olen])
        }
    }
}
