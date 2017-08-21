import Core
import libc

fileprivate let decodeLookupTable: [UInt8] = [
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 62, 64, 62, 64, 63,
    52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 64, 64, 64, 64, 64, 64,
    64, 00, 01, 02, 03, 04, 05, 06, 07, 08, 09, 10, 11, 12, 13, 14,
    15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 64, 64, 64, 64, 63,
    64, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
    41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
]

fileprivate let encodeTable = [UInt8]("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".utf8)

public final class Base64Encoder : Stream {
    public typealias Input = ByteBuffer
    public typealias Output = ByteBuffer
    
    public var outputStream: ((ByteBuffer) -> ())?
    public var errorStream: BaseStream.ErrorHandler?
    
    public struct UnknownFailure : Error {}
    
    fileprivate static func encode(_ buffer: ByteBuffer, toPointer pointer: UnsafeMutablePointer<UInt8>, capacity: Int, finish: Bool) -> (complete: Bool, filled: Int, consumed: Int) {
        guard let input = buffer.baseAddress else {
            return (true, 0, 0)
        }
        
        var inputPosition = 0
        var outputPosition = 0
        var processedByte: UInt8
        
        func byte(at pos: UInt8) -> UInt8 {
            return encodeTable[numericCast(pos)]
        }
        
        func finishable() -> Bool {
            guard finish else {
                guard inputPosition &+ 3 < buffer.count else {
                    return false
                }
                
                return true
            }
            
            return true
        }
        
        while inputPosition < buffer.count, outputPosition &+ 4 < capacity, finishable() {
            defer {
                inputPosition = inputPosition &+ 3
                outputPosition = outputPosition &+ 4
            }
            
            pointer[outputPosition] = byte(at: (input[inputPosition] & 0xfc) >> 2)
            
            processedByte = (input[inputPosition] & 0x03) << 4
            
            guard inputPosition &+ 1 < buffer.count else {
                pointer[outputPosition &+ 1] = byte(at: processedByte)
                
                // '=='
                pointer[outputPosition &+ 2] = 0x3d
                pointer[outputPosition &+ 3] = 0x3d
                
                return (true, outputPosition &+ 4, inputPosition &+ 1)
            }
            
            processedByte |= (input[inputPosition &+ 1] & 0xf0) >> 4
            pointer[outputPosition &+ 1] = byte(at: processedByte)
            processedByte = (input[inputPosition &+ 1] & 0x0f) << 2
            
            guard inputPosition &+ 2 < buffer.count else {
                pointer[outputPosition &+ 2] = byte(at: processedByte)
                
                // '='
                pointer[outputPosition &+ 3] = 0x3d
                return (true, outputPosition &+ 4, inputPosition &+ 2)
            }
            
            processedByte |= (input[inputPosition &+ 2] & 0xc0) >> 6
            pointer[outputPosition &+ 2] = byte(at: processedByte)
            pointer[outputPosition &+ 3] = byte(at: input[inputPosition &+ 2] & 0x3f)
        }
        
        return (inputPosition == buffer.count, outputPosition, inputPosition)
    }
    
    public static func encode(buffer: ByteBuffer) throws -> MutableByteBuffer {
        let allocatedCapacity = (buffer.count * 4) / 3
        
        let pointer = UnsafeMutablePointer<UInt8>.allocate(capacity: allocatedCapacity)
        pointer.initialize(to: 0, count: allocatedCapacity)
        
        let result = Base64Encoder.encode(buffer, toPointer: pointer, capacity: allocatedCapacity, finish: true)
        
        guard result.complete else {
            pointer.deinitialize(count: allocatedCapacity)
            pointer.deallocate(capacity: allocatedCapacity)
            throw UnknownFailure()
        }
        
        return MutableByteBuffer(start: pointer, count: allocatedCapacity)
    }
    
    let allocatedCapacity: Int
    var currentCapacity = 0
    let pointer: UnsafeMutablePointer<UInt8>
    var remainder = [UInt8]()
    
    public init(allocatedCapacity: Int = 65_507) {
        self.allocatedCapacity = (allocatedCapacity * 4) / 3
        self.pointer = UnsafeMutablePointer<UInt8>.allocate(capacity: self.allocatedCapacity)
        self.pointer.initialize(to: 0, count: self.allocatedCapacity)
    }
    
    public func inputStream(_ input: ByteBuffer) {
        var input = input
        
        func process() {
            self.remainder = []
            
            let (complete, capacity, consumed) = Base64Encoder.encode(input, toPointer: pointer, capacity: allocatedCapacity, finish: false)
            self.currentCapacity = capacity
            
            let writeBuffer = ByteBuffer(start: pointer, count: capacity)
            
            self.outputStream?(writeBuffer)
            
            guard complete else {
                remainder.append(contentsOf: ByteBuffer(start: input.baseAddress?.advanced(by: consumed), count: input.count &- consumed))
                return
            }
        }
        
        guard remainder.count == 0 else {
            guard let inputPointer = input.baseAddress else {
                return
            }
            
            let newPointer = UnsafeMutablePointer<UInt8>.allocate(capacity: remainder.count &+ input.count)
            newPointer.initialize(to: 0, count: remainder.count &+ input.count)
            
            newPointer.assign(from: remainder, count: remainder.count)
            newPointer.advanced(by: remainder.count).assign(from: inputPointer, count: input.count)
            
            process()
            return
        }
        
        process()
    }
}
