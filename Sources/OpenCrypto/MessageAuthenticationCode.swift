public protocol MessageAuthenticationCode : ContiguousBytes, CustomStringConvertible, Hashable, Sequence where Self.Element == UInt8 {
    static var byteCount: Int { get }
}
