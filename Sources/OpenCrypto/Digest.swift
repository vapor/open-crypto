public protocol Digest: ContiguousBytes, CustomStringConvertible, Hashable, Sequence
    where Self.Element == UInt8
{
    static var byteCount: Int { get }
}
