import CNIOOpenSSL

/// OpenSSLCipherAlgorithm represents a common set of properties shared by
/// OpenSSL cipher algorithms.
public protocol OpenSSLCipherAlgorithm {
    /// An initializer accepting the EVP_CIPHER to work with
    init(c: UnsafePointer<EVP_CIPHER>)

    /// OpenSSL `EVP_CIPHER` context.
    var c: UnsafePointer<EVP_CIPHER> { get }

    /// Returns the OpenSSL NID type for this algorithm.
    var type: Int32 { get }

    /// This cipher's required key length.
    var keySize: Int32 { get }

    /// This cipher's required initialization vector length.
    var ivSize: Int32 { get }

    /// This cipher's block size, used internally to allocate "out" buffers.
    var blockSize: Int32 { get }
}

/// An extension providing a default implementation for standard
/// OpenSSL EVP versions of this protocol
extension OpenSSLCipherAlgorithm {
    /// See `OpenSSLCipherAlgorithm`
    public var type: Int32 {
        return EVP_CIPHER_type(c)
    }

    /// See `OpenSSLCipherAlgorithm`
    public var keySize: Int32 {
        return EVP_CIPHER_key_length(c)
    }

    /// See `OpenSSLCipherAlgorithm`
    public var ivSize: Int32 {
        return EVP_CIPHER_iv_length(c)
    }

    /// See `OpenSSLCipherAlgorithm`
    public var blockSize: Int32 {
        return EVP_CIPHER_block_size(c)
    }
}
