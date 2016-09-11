/**
    Hashing method for calculating
    the HMAC authentication.
*/
extension Hash {
    public enum Method {
        case sha1
        case sha224
        case sha256
        case sha384
        case sha512
        case md4
        case md5
        case ripemd160
    }
}
