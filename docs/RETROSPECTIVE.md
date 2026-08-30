# Retrospective — DiffPrivLab (Cycle 32)

## What went well
- **Correct Laplace mechanism**: Implemented inverse CDF method for Laplace noise generation since Python's `random` module doesn't have `laplace()` until 3.14+
- **Advanced composition theorem**: Correctly implemented the Dwork-Rothblum-Singer bound using the sqrt composition formula
- **Budget accountant**: Clean enforcement with clear error messages when budget is exceeded

## Lessons learned
1. **Python 3.14 compatibility**: `random.laplace()` was added in Python 3.14; need to implement inverse CDF manually for compatibility with 3.9+
2. **Advanced composition formula**: The formula `sqrt(2k·ln(1/δ'))·ε + ε·(e^ε - 1)` requires careful implementation; the sqrt approximation `sqrt(eps_approx² + ε²) - ε` is more numerically stable
3. **Delta handling in tests**: When testing with δ > 0, must pass delta=0.001 to constructor, not rely on default 0.0
4. **Mutation gates are essential**: M1/M2 caught real bugs where the accountant or composition was broken

## Technical debt
- None — all tests pass, ruff clean, bandit clean
- Could add ExponentialMechanism tests with more outcomes
- Could add hypothesis-based fuzzing for edge cases

## Verification harness quality
- 31 tests covering all properties (P1-P5, M1-M2)
- Harness is deterministic (seeded RNG) and reproducible
- Mutation gates are non-vacuous (M1/M2 both detect their respective mutations)
- Composition theorems tested against known bounds
