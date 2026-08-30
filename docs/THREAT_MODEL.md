# Security Threat Model

## Threats

### 1. Budget Exhaustion
- Malicious query could drain entire privacy budget
- **Mitigation**: BudgetAccountant enforces hard limits; raises BudgetExhaustionError

### 2. Incorrect Sensitivity
- Underestimating sensitivity leads to insufficient noise
- **Mitigation**: Empirical sensitivity computation with multiple dataset pairs

### 3. Composition Violations
- Applying composition theorems incorrectly (e.g., using basic instead of advanced)
- **Mitigation**: Both composition theorems implemented and tested separately

### 4. Noise Distribution Bugs
- Using wrong distribution (e.g., Gaussian instead of Laplace for ε-DP)
- **Mitigation**: Mechanism-specific tests verify correct noise scales

### 5. Delta Overflow
- δ > 1 or δ < 0 breaks privacy guarantees
- **Mitigation**: Constructor validation rejects invalid deltas

## Assumptions
- Queries are applied to the same dataset (no dataset changes between queries)
- Mechanisms are applied independently (no adaptive composition bugs)
- Random seed is fixed for reproducibility in verification

## Security Measures
- Strict input validation on all constructors
- Budget enforcement with clear error messages
- Zero external dependencies (no network I/O)
- Deterministic seeded RNG for reproducible tests
- Bandit clean (0 high/medium findings)
