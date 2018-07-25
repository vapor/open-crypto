import CNIOOpenSSL

/// OpenSSLCipherAlgorithm represents a common set of properties shared by
/// OpenSSL cipher algorithms.
public protocol OpenSSLCipherAlgorithm {
    var c: UnsafePointer<EVP_CIPHER> { get }
    init(c: UnsafePointer<EVP_CIPHER>)

    var type: Int32 { get }
    var keySize: Int32 { get }
    var ivSize: Int32 { get }
    var blockSize: Int32 { get }
}

/// An extension providing a default implementation for standard
/// OpenSSL EVP versions of this protocol
extension OpenSSLCipherAlgorithm {
    /// Returns the OpenSSL NID type for this algorithm.
    public var type: Int32 {
        return EVP_CIPHER_type(c)
    }

    /// This cipher's required key length.
    public var keySize: Int32 {
        return EVP_CIPHER_key_length(c)
    }

    /// This cipher's required initialization vector length.
    public var ivSize: Int32 {
        return EVP_CIPHER_iv_length(c)
    }

    /// This cipher's block size, used internally to allocate "out" buffers.
    public var blockSize: Int32 {
        return EVP_CIPHER_block_size(c)
    }
}
