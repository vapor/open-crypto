import CLibreSSL
import Essentials
import Core

public final class Cipher {
    public let method: Method
    public let key: Bytes
    public let iv: Bytes?

    /**
        Creates a cipher for encrypting and decrypting
        byte streams using the supplied key and optionally
        initialization vector.
     
        - method: The cipher method to use
        - key: The crypto key
        - iv: Optional initialization vector, defaults to the key if `useIV` is true.
     
        Note: Some cipher methods may require an intialization vector
        to work properly.
    */
    public init(
        _ method: Method,
        key: Bytes,
        iv: Bytes? = nil
    ) throws {
        let keyLen = Int(EVP_CIPHER_key_length(method.evp))
        guard key.count == keyLen else {
            throw Error.invalidKeyLength(expected: keyLen)
        }

        self.method = method
        self.key = key

        if let iv = iv {
            let ivLen = Int(EVP_CIPHER_iv_length(method.evp))
            guard ivLen == iv.count else {
                throw Error.invalidInitializationVectorLength(expected: ivLen)
            }
            self.iv = iv
        } else {
            self.iv = nil
        }
    }

    public enum Error: Swift.Error {
        case initialize
        case update
        case finalize
        case invalidKeyLength(expected: Int)
        case invalidInitializationVectorLength(expected: Int)
    }

    public func encrypt(_ stream: ByteStream) throws -> Bytes {
        return try libreCipher(
            stream: stream,
            initialize: { EVP_EncryptInit($0, $1, $2, $3) },
            update: EVP_EncryptUpdate,
            final: EVP_EncryptFinal
        )
    }

    public func decrypt(_ stream: ByteStream) throws -> Bytes {
        return try libreCipher(
            stream: stream,
            initialize: { EVP_DecryptInit($0, $1, $2, $3) },
            update: EVP_DecryptUpdate,
            final: EVP_DecryptFinal
        )
    }

    private func libreCipher(
        stream: ByteStream,
        initialize: (
            UnsafeMutablePointer<EVP_CIPHER_CTX>,
            UnsafePointer<EVP_CIPHER>,
            UnsafePointer<UInt8>,
            UnsafePointer<UInt8>?
        ) -> Int32,
        update: (
            UnsafeMutablePointer<EVP_CIPHER_CTX>,
            UnsafeMutablePointer<UInt8>,
            UnsafeMutablePointer<Int32>,
            UnsafePointer<UInt8>,
            Int32
        ) -> Int32,
        final: (
            UnsafeMutablePointer<EVP_CIPHER_CTX>,
            UnsafeMutablePointer<UInt8>,
            UnsafeMutablePointer<Int32>
        ) -> Int32
    ) throws -> Bytes {
        var ctx = EVP_CIPHER_CTX()

        guard initialize(&ctx, method.evp, key, iv) == 1 else {
            throw Error.initialize
        }

        var parsed: Bytes = []

        let bufferLength = Int(1024 + EVP_MAX_BLOCK_LENGTH)
        let buffer = UnsafeMutablePointer<Byte>.allocate(capacity: bufferLength)
        defer {
            buffer.deinitialize()
            buffer.deallocate(capacity: bufferLength)
        }

        while !stream.closed {
            var newLength: Int32 = 0
            let bytes = try stream.next()
            guard update(&ctx, buffer, &newLength, bytes, Int32(bytes.count)) == 1 else {
                throw Error.update
            }

            let bufferPointer = UnsafeMutableBufferPointer(start: buffer, count: Int(newLength))
            let newParsed = Array(bufferPointer)
            parsed += newParsed
        }

        var endLength: Int32 = 0
        guard final(&ctx, buffer, &endLength) == 1 else {
            throw Error.finalize
        }

        let bufferPointer = UnsafeMutableBufferPointer(start: buffer, count: Int(endLength))
        let end = Array(bufferPointer)
        parsed += end
        
        return parsed
    }
}

extension Cipher {
    public func encrypt(_ bytes: Bytes) throws -> Bytes {
        let stream = BasicByteStream(bytes)
        return try encrypt(stream)
    }

    public func decrypt(_ bytes: Bytes) throws -> Bytes {
        let stream = BasicByteStream(bytes)
        return try decrypt(stream)
    }
}

public enum Method {
    case blowfish(BlowfishMode)
    public enum BlowfishMode {
        case cbc
        case ecb
        case ofb
        case cfb64
    }

    case des(DESMode)
    public enum DESMode {
        case none(NoneMode)
        public enum NoneMode {
            case cfb1
            case cfb8
            case cfb64
            case ofb
            case ecb
            case cbc
        }

        case ede(EDEMode)
        public enum EDEMode {
            case none
            case cfb64
            case ofb
            case ecb
            case cbc
        }

        case ede3(EDE3Mode)
        public enum EDE3Mode {
            case none
            case cfb1
            case cfb8
            case cfb64
            case ofb
            case ecb
            case cbc
        }
    }

    case rc2(RC2Mode)
    public enum RC2Mode {
        case ecb
        case ofb
        case cbc
        case cfb64
        case fortyCBC
        case sixtyFourCBC
    }

    case rc4(RC4Mode)
    public enum RC4Mode {
        case none
        case forty
        case hmacMD5
    }

    case idea(IDEAMode)
    public enum IDEAMode {
        case ecb
        case ofb
        case cbc
        case cfb64
    }

    case chacha20

    case cast5(CAST5Mode)
    public enum CAST5Mode {
        case ecb
        case ofb
        case cbc
        case cfb64
    }

    case aes128(AES128Mode)
    public enum AES128Mode {
        case ecb
        case cbc
        case cbcHMACSHA1
        case cfb1
        case cfb8
        case cfb128
        case ofb
        case ctr
        case gcm
        case xts
    }

    case aes192(AES192Mode)
    public enum AES192Mode {
        case ecb
        case cbc
        case cfb1
        case cfb8
        case cfb128
        case ofb
        case ctr
        case gcm
    }

    case aes256(AES256Mode)
    public enum AES256Mode {
        case ecb
        case cbc
        case cbcHMACSHA1
        case cfb1
        case cfb8
        case cfb128
        case ofb
        case ctr
        case gcm
        case xts
    }

    case camellia128(Camellia128Mode)
    public enum Camellia128Mode {
        case ecb
        case cbc
        case cfb1
        case cfb8
        case cfb128
        case ofb
    }

    case camellia192(Camellia192Mode)
    public enum Camellia192Mode {
        case ecb
        case cbc
        case cfb1
        case cfb8
        case cfb128
        case ofb
    }

    case camellia256(Camellia256Mode)
    public enum Camellia256Mode {
        case ecb
        case cbc
        case cfb1
        case cfb8
        case cfb128
        case ofb
    }

    case gost2814789(GOST2814789Mode)
    public enum GOST2814789Mode {
        case ecb
        case cfb64
        case cnt
    }
}

extension Method {
    var evp: UnsafePointer<EVP_CIPHER> {
        switch self {
        case .blowfish(let mode):
            switch mode {
            case .cbc:
                return EVP_bf_cbc()
            case .ecb:
                return EVP_bf_cbc()
            case .ofb:
                return EVP_bf_ofb()
            case .cfb64:
                return EVP_bf_cfb64()    
            }
        case .des(let mode):
            switch mode {
            case .none(let submode):
                switch submode {
                case .cfb1:
                    return EVP_des_cfb1()
                case .cfb8:
                    return EVP_des_cfb8()
                case .cfb64:
                    return EVP_des_cfb64()
                case .ofb:
                    return EVP_des_ofb()
                case .ecb:
                    return EVP_des_ecb()
                case .cbc:
                    return EVP_des_cbc()
                }
            case .ede(let submode):
                switch submode {
                case .none:
                    return EVP_des_ede()
                case .cfb64:
                    return EVP_des_ede_cfb64()
                case .ofb:
                    return EVP_des_ede_ofb()
                case .ecb:
                    return EVP_des_ede_ecb()
                case .cbc:
                    return EVP_des_ede_cbc()
                }
            case .ede3(let submode):
                switch submode {
                case .none:
                    return EVP_des_ede3()
                case .cfb1:
                    return EVP_des_ede3_cfb1()
                case .cfb8:
                    return EVP_des_ede3_cfb8()
                case .cfb64:
                    return EVP_des_ede3_cfb64()
                case .ofb:
                    return EVP_des_ede3_ofb()
                case .ecb:
                    return EVP_des_ede3_ecb()
                case .cbc:
                    return EVP_des_ede3_cbc()
                }
            }
        case .rc2(let mode):
            switch mode {
            case .ecb:
                return EVP_rc2_ecb()
            case .ofb:
                return EVP_rc2_ofb()
            case .cbc:
                return EVP_rc2_ofb()
            case .cfb64:
                return EVP_rc2_cfb64()
            case .fortyCBC:
                return EVP_rc2_40_cbc()
            case .sixtyFourCBC:
                return EVP_rc2_64_cbc()
            }
        case .rc4(let mode):
            switch mode {
            case .none:
                return EVP_rc4()
            case .forty:
                return EVP_rc4_40()
            case .hmacMD5:
                return EVP_rc4_hmac_md5()
            }
        case .idea(let mode):
            switch mode {
            case .ecb:
                return EVP_idea_ecb()
            case .ofb:
                return EVP_idea_ofb()
            case .cbc:
                return EVP_idea_cbc()
            case .cfb64:
                return EVP_idea_cfb64()
            }
        case .chacha20:
            return EVP_chacha20()
        case .cast5(let mode):
            switch mode {
            case .ecb:
                return EVP_cast5_ecb()
            case .ofb:
                return EVP_cast5_ofb()
            case .cbc:
                return EVP_cast5_cbc()
            case .cfb64:
                return EVP_cast5_cfb64()
            }
        case .aes128(let mode):
            switch mode {
            case .ecb:
                return EVP_aes_128_ecb()
            case .cbc:
                return EVP_aes_128_cbc()
            case .cbcHMACSHA1:
                return EVP_aes_128_cbc_hmac_sha1()
            case .cfb1:
                return EVP_aes_128_cfb1()
            case .cfb8:
                return EVP_aes_128_cfb8()
            case .cfb128:
                return EVP_aes_128_cfb128()
            case .ofb:
                return EVP_aes_128_ofb()
            case .ctr:
                return EVP_aes_128_ctr()
            case .gcm:
                return EVP_aes_128_gcm()
            case .xts:
                return EVP_aes_128_xts()
            }
        case .aes192(let mode):
            switch mode {
            case .ecb:
                return EVP_aes_192_ecb()
            case .cbc:
                return EVP_aes_192_cbc()
            case .cfb1:
                return EVP_aes_192_cfb1()
            case .cfb8:
                return EVP_aes_192_cfb8()
            case .cfb128:
                return EVP_aes_192_cfb128()
            case .ofb:
                return EVP_aes_192_ofb()
            case .ctr:
                return EVP_aes_192_ctr()
            case .gcm:
                return EVP_aes_192_gcm()
            }
        case .aes256(let mode):
            switch mode {
            case .ecb:
                return EVP_aes_256_ecb()
            case .cbc:
                return EVP_aes_256_cbc()
            case .cbcHMACSHA1:
                return EVP_aes_256_cbc_hmac_sha1()
            case .cfb1:
                return EVP_aes_256_cfb1()
            case .cfb8:
                return EVP_aes_256_cfb8()
            case .cfb128:
                return EVP_aes_256_cfb128()
            case .ofb:
                return EVP_aes_256_ofb()
            case .ctr:
                return EVP_aes_256_ctr()
            case .gcm:
                return EVP_aes_256_gcm()
            case .xts:
                return EVP_aes_256_xts()
            }
        case .camellia128(let mode):
            switch mode {
            case .ecb:
                return EVP_camellia_128_ecb()
            case .cbc:
                return EVP_camellia_128_cbc()
            case .cfb1:
                return EVP_camellia_128_cfb1()
            case .cfb8:
                return EVP_camellia_128_cfb8()
            case .cfb128:
                return EVP_camellia_128_cfb128()
            case .ofb:
                return EVP_camellia_128_ofb()
            }
        case .camellia192(let mode):
            switch mode {
            case .ecb:
                return EVP_camellia_192_ecb()
            case .cbc:
                return EVP_camellia_192_cbc()
            case .cfb1:
                return EVP_camellia_192_cfb1()
            case .cfb8:
                return EVP_camellia_192_cfb8()
            case .cfb128:
                return EVP_camellia_192_cfb128()
            case .ofb:
                return EVP_camellia_192_ofb()
            }
        case .camellia256(let mode):
            switch mode {
            case .ecb:
                return EVP_camellia_256_ecb()
            case .cbc:
                return EVP_camellia_256_cbc()
            case .cfb1:
                return EVP_camellia_256_cfb1()
            case .cfb8:
                return EVP_camellia_256_cfb8()
            case .cfb128:
                return EVP_camellia_256_cfb128()
            case .ofb:
                return EVP_camellia_256_ofb()
            }
        case .gost2814789(let mode):
            switch mode {
            case .ecb:
                return EVP_gost2814789_ecb()
            case .cfb64:
                return EVP_gost2814789_cfb64()
            case .cnt:
                return EVP_gost2814789_cnt()
            }
        }
    }
}
