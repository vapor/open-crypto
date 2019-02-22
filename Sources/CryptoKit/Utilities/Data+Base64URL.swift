import struct Foundation.Data

extension Data {
    /// Decodes a base64-url encoded string to data.
    ///
    /// https://tools.ietf.org/html/rfc4648#page-7
    public init?(base64URLEncoded: String, options: Data.Base64DecodingOptions = []) {
        self.init(base64Encoded: base64URLEncoded.base64URLUnescaped(), options: options)
    }
    
    /// Decodes base64-url encoded data.
    ///
    /// https://tools.ietf.org/html/rfc4648#page-7
    public init?(base64URLEncoded: Data, options: Data.Base64DecodingOptions = []) {
        self.init(base64Encoded: base64URLEncoded.base64URLUnescaped(), options: options)
    }
    
    /// Encodes data to a base64-url encoded string.
    ///
    /// https://tools.ietf.org/html/rfc4648#page-7
    ///
    /// - parameter options: The options to use for the encoding. Default value is `[]`.
    /// - returns: The base64-url encoded string.
    public func base64URLEncodedString(options: Data.Base64EncodingOptions = []) -> String {
        return base64EncodedString(options: options).base64URLEscaped()
    }
    
    /// Encodes data to base64-url encoded data.
    ///
    /// https://tools.ietf.org/html/rfc4648#page-7
    ///
    /// - parameter options: The options to use for the encoding. Default value is `[]`.
    /// - returns: The base64-url encoded data.
    public func base64URLEncodedData(options: Data.Base64EncodingOptions = []) -> Data {
        return base64EncodedData(options: options).base64URLEscaped()
    }
}

/// MARK: String Escape
extension String {
    /// Converts a base64-url encoded string to a base64 encoded string.
    ///
    /// https://tools.ietf.org/html/rfc4648#page-7
    public func base64URLUnescaped() -> String {
        let replaced = replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        /// https://stackoverflow.com/questions/43499651/decode-base64url-to-base64-swift
        let padding = replaced.count % 4
        if padding > 0 {
            return replaced + String(repeating: "=", count: 4 - padding)
        } else {
            return replaced
        }
    }
    
    /// Converts a base64 encoded string to a base64-url encoded string.
    ///
    /// https://tools.ietf.org/html/rfc4648#page-7
    public func base64URLEscaped() -> String {
        return replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
    
    /// Converts a base64-url encoded string to a base64 encoded string.
    ///
    /// https://tools.ietf.org/html/rfc4648#page-7
    public mutating func base64URLUnescape() {
        self = base64URLUnescaped()
    }
    
    /// Converts a base64 encoded string to a base64-url encoded string.
    ///
    /// https://tools.ietf.org/html/rfc4648#page-7
    public mutating func base64URLEscape() {
        self = base64URLEscaped()
    }
}

/// MARK: Data Escape
extension Data {
    /// Converts base64-url encoded data to a base64 encoded data.
    ///
    /// https://tools.ietf.org/html/rfc4648#page-7
    public mutating func base64URLUnescape() {
        for (i, byte) in enumerated() {
            switch byte {
            case 0x2D: self[i] = 0x2B
            case 0x5F: self[i] = 0x2F
            default: break
            }
        }
        /// https://stackoverflow.com/questions/43499651/decode-base64url-to-base64-swift
        let padding = count % 4
        if padding > 0 {
            self += Data(repeating: 0x3D, count: 4 - count % 4)
        }
    }
    
    /// Converts base64 encoded data to a base64-url encoded data.
    ///
    /// https://tools.ietf.org/html/rfc4648#page-7
    public mutating func base64URLEscape() {
        for (i, byte) in enumerated() {
            switch byte {
            case 0x2B: self[i] = 0x2D
            case 0x2F: self[i] = 0x5F
            default: break
            }
        }
        self = split(separator: 0x3D).first ?? .init()
    }
    
    /// Converts base64-url encoded data to a base64 encoded data.
    ///
    /// https://tools.ietf.org/html/rfc4648#page-7
    public func base64URLUnescaped() -> Data {
        var data = self
        data.base64URLUnescape()
        return data
    }
    
    /// Converts base64 encoded data to a base64-url encoded data.
    ///
    /// https://tools.ietf.org/html/rfc4648#page-7
    public func base64URLEscaped() -> Data {
        var data = self
        data.base64URLEscape()
        return data
    }
}
