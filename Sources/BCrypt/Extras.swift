extension String {
    subscript (i: Int) -> Character {
        return self[index(self.startIndex, offsetBy: i)]
    }

    subscript (i: Int) -> String {
        return String(self[i] as Character)
    }

    subscript (r: Range<Int>) -> String {
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
