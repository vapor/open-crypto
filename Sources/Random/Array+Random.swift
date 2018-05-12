import Foundation

extension Array {
    /// Returns a random element from this array using `OSRandom`.
    public var random: Element? {
        guard count > 0 else {
            return nil
        }
        
        let random = OSRandom()
            .generateData(count: MemoryLayout<UInt>.size)
            .cast(to: UInt.self)
        
        let index = random % UInt(count)
        return self[Int(index)]
    }
    
    /// Returns the elements of this array, sorted randomly using `OSRandom`.
    public func randomized() -> [Element] {
        var original = self
        var randomized: [Element] = []
        
        let random = OSRandom()
            .generateData(count: MemoryLayout<UInt>.size)
            .cast(to: UInt.self)
        
        while original.count > 0 {
            let index = Int(random % UInt(original.count))
            let draw = original.remove(at: index)
            randomized.append(draw)
        }
        
        return randomized
    }
}
