# DiffPrivLab — Verified Differential Privacy Engine

A from-scratch differential privacy library with a formal verification harness proving:
- **Epsilon budget accounting**: Total privacy loss never exceeds the allocated budget
- **Composition theorems**: Basic and advanced composition theorems are mathematically correct
- **Sensitivity correctness**: L0, L1, and L2 sensitivities are computed correctly
- **Mechanism correctness**: Laplace and Gaussian mechanisms satisfy their DP guarantees
- **Monotonicity**: Adding queries never decreases privacy loss

```bash
python -m diffprivlab verify --seed 42 --trials 100
```

## Features

- **Core mechanisms**: Laplace, Gaussian, Exponential, Geometric
- **Privacy budget accountant**: Tracks cumulative epsilon/delta across queries
- **Composition theorems**: Basic composition, advanced composition, moments accountant
- **Sensitivity analyzer**: Automatic sensitivity computation for common queries
- **Verification harness**: Property + mutation testing as a CI exit-code gate

## Verification

```bash
python -m diffprivlab verify --seed 42 --trials 100
```

Property gates:
- **P1 Epsilon budget**: Total privacy loss ≤ allocated budget
- **P2 Composition theorem**: Basic composition holds (ε_total = Σε_i)
- **P3 Advanced composition**: Advanced composition bound holds (δ improves)
- **P4 Sensitivity correctness**: Computed sensitivity matches theoretical
- **P5 Monotonicity**: More queries = more privacy loss
- **M1/M2 Mutation**: Broken accountant/mechanism detected by harness
