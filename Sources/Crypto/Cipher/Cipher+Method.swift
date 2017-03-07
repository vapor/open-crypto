import CLibreSSL

extension Cipher {
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
                // case cfb1 // unstable https://github.com/01org/luv-yocto/blob/master/meta/recipes-connectivity/openssl/openssl/fix-cipher-des-ede3-cfb1.patch
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
            // case cbcHMACSHA1 // crashes
            case cfb1
            case cfb8
            case cfb128
            case ofb
            case ctr
            // case gcm // https://github.com/vapor/crypto/issues/16
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
            // case gcm // https://github.com/vapor/crypto/issues/16
        }

        case aes256(AES256Mode)
        public enum AES256Mode {
            case ecb
            case cbc
            // case cbcHMACSHA1 // crashes
            case cfb1
            case cfb8
            case cfb128
            case ofb
            case ctr
            // case gcm // https://github.com/vapor/crypto/issues/16
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
}

extension Cipher.Method {
    public var evp: UnsafePointer<EVP_CIPHER> {
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
                //case .cfb1:
                //    return EVP_des_ede3_cfb1()
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
            //case .cbcHMACSHA1:
            //    return EVP_aes_128_cbc_hmac_sha1()
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
            //case .gcm:
            //    return EVP_aes_128_gcm()
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
            //case .gcm:
            //    return EVP_aes_192_gcm()
            }
        case .aes256(let mode):
            switch mode {
            case .ecb:
                return EVP_aes_256_ecb()
            case .cbc:
                return EVP_aes_256_cbc()
            //case .cbcHMACSHA1:
            //    return EVP_aes_256_cbc_hmac_sha1()
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
            //case .gcm:
            //    return EVP_aes_256_gcm()
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
