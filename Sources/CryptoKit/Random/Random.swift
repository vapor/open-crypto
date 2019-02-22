public struct RandomGenerator: DataGenerator {
    public func generateData(count: Int) throws -> [UInt8] {
        var data = [UInt8]()
        for _ in 0..<count {
            data.append(.random())
        }
        return data
    }
}

extension FixedWidthInteger {
    public static func random() -> Self {
        return Self.random(in: .min ... .max)
    }
    
    public static func random<T>(using generator: inout T) -> Self
        where T : RandomNumberGenerator
    {
        return Self.random(in: .min ... .max, using: &generator)
    }
}

extension Array where Element: FixedWidthInteger {
    public static func random(count: Int) -> [Element] {
        var array: [Element] = .init(repeating: 0, count: count)
        (0..<count).forEach { array[$0] = Element.random() }
        return array
    }
    
    public static func random<T>(count: Int, using generator: inout T) -> [Element]
        where T: RandomNumberGenerator
    {
        var array: [Element] = .init(repeating: 0, count: count)
        (0..<count).forEach { array[$0] = Element.random() }
        return array
    }
}
