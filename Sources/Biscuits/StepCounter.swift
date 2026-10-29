struct StepCounter: Hashable {
    var remaining: Int?

    mutating func step() throws {
        switch self.remaining {
        case .some(0): throw Biscuit.EvaluationError.tooManySteps
        case .some(let n): self.remaining = n - 1
        default: return
        }
    }
}
