extension Hash {
    public static func random(_ m: Method) throws -> Bytes {
        return try random(m, Random.self)
    }

    public static func random<R: RandomProtocol & EmptyInitializable>(_ m: Method, _ r: R.Type) throws -> Bytes {
        let r = try r.init()
        return try random(m, r)
    }

    public static func random<R: RandomProtocol>(_ m: Method, _ r: R) throws -> Bytes {
        let message = try r.bytes(count: 64)
        return try Hash.make(m, message)
    }
}
