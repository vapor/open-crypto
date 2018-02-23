import Async
import Bits
import Foundation

public final class Base64Stream: Async.Stream {
    /// Accepts Base64 encoded byte streams
    public typealias Input = ByteBuffer

    /// Outputs  byte streams
    public typealias Output = ByteBuffer

    /// The underlying coder
    private var base64: Base64

    /// Downstream input stream accepting byte buffers
    private var downstream: AnyInputStream<ByteBuffer>?

    /// The bytes that couldn't be parsed from the previous buffer
    private var remainder: Data

    /// Creates a Base64 coder with default buffer size and encoding
    init(base64: Base64) {
        self.base64 = base64
        remainder = .init()
        self.remainder.reserveCapacity(4)
    }

    public func input(_ event: InputEvent<ByteBuffer>) {
        switch event {
        case .close:
            do {
                try complete()
                downstream?.close()
            } catch {
                downstream?.error(error)
            }
        case .error(let error): downstream?.error(error)
        case .next(let input, let ready):
            do {
                try processIncludingRemainder(input: input, ready: ready)
            } catch {
                downstream?.error(error)
            }
        }
    }

    /// See OutputStream.onOutput
    public func output<I>(to inputStream: I) where I: Async.InputStream, ByteBuffer == I.Input {
        downstream = AnyInputStream(inputStream)
    }

    /// Processed the `input`'s `ByteBuffer` by Base64-encoding it
    ///
    /// Calls the `OutputHandler` with the Base64-encoded data
    private func processIncludingRemainder(input: ByteBuffer, ready: Promise<Void>) throws {
        // If the remainder from previous processing attempts is not empty
        if remainder.count != 0 {
            // Create a new buffer for the input + the remainder
            let newPointerLength = remainder.count &+ input.count
            let newPointer = MutableBytesPointer.allocate(capacity: newPointerLength)
            newPointer.initialize(repeating: 0, count: newPointerLength)

            defer {
                newPointer.deinitialize(count: newPointerLength)
                newPointer.deallocate()
            }

            // Set the remainder
            remainder.withUnsafeBytes { pointer in
                _ = memcpy(newPointer, pointer, remainder.count)
            }

            // Appends the input
            if input.count > 0, let inputPointer = input.baseAddress {
                memcpy(newPointer.advanced(by: remainder.count), inputPointer, input.count)
            }

            try process(input: ByteBuffer(start: newPointer, count: newPointerLength), ready: ready)
        } else {
            try process(input: input, ready: ready)
        }
    }

    private func process(input: ByteBuffer, ready: Promise<Void>) throws {
        self.remainder = Data()

        // Process the bytes into the local buffer `pointer`
        let (complete, capacity, consumed) = try base64.process(input, toPointer: base64.pointer, capacity: base64.allocatedCapacity, finish: false)
        base64.currentCapacity = capacity

        // Swift doesn't recognize that Output == ByteBuffer
        // Create a buffer referencing the ouput pointer and the outputted capacity
        let writeBuffer = ByteBuffer(start: base64.pointer, count: capacity)

        // Write the output buffer to the output stream
        if writeBuffer.count > 0 {
            downstream?.next(writeBuffer, ready)
        } else {
            ready.complete()
        }

        // If processing is complete
        if !complete {
            // Append any unprocessed data to the remainder storage
            remainder.append(
                contentsOf: ByteBuffer(
                    start: input.baseAddress?.advanced(by: consumed),
                    count: input.count &- consumed
                )
            )
        }
    }

    /// Completes the stream, flushing all remaining bytes by encoding them
    ///
    /// Any data after this will reopen the stream
    private func complete() throws {
        print(#function)
        if remainder.count > 0 {
            let buffer: ByteBuffer = try remainder.withUnsafeBytes { (pointer: BytesPointer) in
                let buffer = ByteBuffer(start: pointer, count: remainder.count)

                /// Process the remainder
                let (_, capacity, _) = try base64.process(buffer, toPointer: base64.pointer, capacity: base64.allocatedCapacity, finish: true)

                /// Create an output buffer (having to force cast an always-success case)
                return ByteBuffer(start: base64.pointer, count: capacity)
            }

            // ignore next ready since we are closing
            _ = downstream?.next(buffer)
        }
    }
}
