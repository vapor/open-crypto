extension DataProtocol {
    func copyBytes() -> [UInt8] {
        var buffer = UnsafeMutableBufferPointer<UInt8>.allocate(capacity: self.count)
        self.copyBytes(to: buffer)
        defer { buffer.deallocate() }
        return .init(buffer)
    }
}

extension Array where Element: FixedWidthInteger {
    static func random(count: Int) -> [Element] {
        var array = self.init()
        for _ in 0..<count {
            array.append(.random(in: Element.min..<Element.max))
        }
        return array
    }
}
