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
