# DiffPrivLab — Verified Differential Privacy Engine

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                     DiffPrivLab Core                                 │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────────┐ │
│  │ LaplaceMechanism│  │GaussianMechanism│  │ExponentialMechanism │ │
│  │  (ε-DP)         │  │  (ε,δ-DP)       │  │  (outcome selection)│ │
│  └────────┬────────┘  └────────┬────────┘  └──────────┬──────────┘ │
│           │                   │                       │             │
│           └───────────────────┼───────────────────────┘             │
│                               │                                     │
│                    ┌──────────▼──────────┐                         │
│                    │  BudgetAccountant   │                         │
│                    │  (tracks cumulative │                         │
│                    │   ε, δ across queries)                        │
│                    └──────────┬──────────┘                         │
│                               │                                     │
│                    ┌──────────▼──────────┐                         │
│                    │  SensitivityAnalyzer│                         │
│                    │  (computes L0, L1,  │                         │
│                    │   L2 sensitivities) │                         │
│                    └─────────────────────┘                         │
│                                                                      │
├─────────────────────────────────────────────────────────────────────┤
│                     Verification Harness                             │
│  P1: Epsilon budget accounting       P4: Sensitivity correctness   │
│  P2: Basic composition theorem       P5: Monotonicity of loss      │
│  P3: Advanced composition bound      M1/M2: Mutation gates         │
└─────────────────────────────────────────────────────────────────────┘
```

## Components

### LaplaceMechanism
- Implements ε-differential privacy using the Laplace distribution
- Noise scale: b = sensitivity / ε
- For query f with L1 sensitivity Δf: add Laplace(0, Δf/ε)

### GaussianMechanism
- Implements (ε, δ)-differential privacy using Gaussian noise
- Noise scale: σ = Δf * √(2 * ln(1.25/δ)) / ε
- Required for compositions where δ > 0

### ExponentialMechanism
- Selects outcomes with probability proportional to exp(ε * u(o) / 2)
- Used for privacy-preserving selection from discrete outcome spaces

### BudgetAccountant
- Tracks cumulative privacy loss across multiple queries
- Enforces ε_total and δ_total budgets
- Implements basic and advanced composition theorems

### SensitivityAnalyzer
- Computes L0, L1, and L2 sensitivities empirically
- Compares query outputs on adjacent datasets
- Validates theoretical sensitivity bounds

## Composition Theorems

### Basic Composition
For k independent mechanisms with ε₁, ε₂, ..., εₖ:
- Total ε = Σ εᵢ
- Total δ = Σ δᵢ

### Advanced Composition
For k mechanisms each (ε, δ)-DP:
- ε' = ε√(2k·ln(1/δ')) + ε(k)(e^ε - 1)
- δ' = δ·k + δ'

Provides tighter bounds than basic composition.
