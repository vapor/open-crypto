extension Hash {
    public static func hash(_ string: String) -> [UInt8] {
        return self.hash([UInt8](string.utf8))
    }
}
