public protocol Digest: ContiguousBytes, CustomStringConvertible, Hashable, Sequence
    where Self.Element == UInt8
{
    static var byteCount: Int { get }
}


extension Digest {
    public func makeIterator() -> Array<UInt8>.Iterator {
        fatalError()
    }
}

extension Digest {
    public static func == (lhs: Self, rhs: Self) -> Bool {
        fatalError()
    }
    
    public static func == (lhs: Self, rhs: ContiguousBytes) -> Bool {
        fatalError()
    }
    
    public var description: String {
        fatalError()
    }
}
