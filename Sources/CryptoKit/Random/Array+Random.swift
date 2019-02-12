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
}
