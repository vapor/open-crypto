import Core

class Chunks: Sequence {
    var remainder = Bytes()
    let chunkSize: Int
    private var _count = 0
    
    var count: Int {
        return _count
    }
    
    init(chunkSize: Int) {
        self.chunkSize = chunkSize
    }
    
    func append(_ byte: Byte) {
        remainder += [byte]
        _count += 1
    }
    
    func append(bytes: Bytes) {
        remainder += bytes
        _count += bytes.count
    }
    
    func append(bytes: BytesSlice) {
        remainder += bytes
        _count += bytes.count
    }
    
    func makeIterator() -> AnyIterator<Bytes> {
        return AnyIterator {
            guard self.remainder.count >= self.chunkSize else {
                return nil
            }
            
            let chunk = Array(self.remainder[0..<self.chunkSize])
            self.remainder.removeFirst(self.chunkSize)
            
            return chunk
        }
    }
}
