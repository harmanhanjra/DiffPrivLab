# Project Specification

## Overview
DiffPrivLab is a verified differential privacy engine that implements core DP mechanisms and proves correctness through a formal verification harness.

## Problem Space
Differential privacy is the gold standard for privacy-preserving data analysis. However, most educational implementations:
1. Stop at showing the math without proving composition theorems
2. Don't verify that budget accounting is correct
3. Lack mutation testing to prove the harness catches bugs

## Components

### Core Mechanisms
1. **LaplaceMechanism**: Adds Laplace noise for ε-DP
   - Scale parameter: b = sensitivity / ε
   - Correct for count/sum queries

2. **GaussianMechanism**: Adds Gaussian noise for (ε, δ)-DP
   - Scale parameter: σ = sensitivity × √(2·ln(1.25/δ)) / ε
   - Required for advanced composition

3. **ExponentialMechanism**: Selects outcomes by utility
   - Probability ∝ exp(ε·u(o)/2)
   - For discrete outcome spaces

### Budget Accountant
- Tracks cumulative ε and δ across queries
- Enforces hard budget limits
- Implements composition theorems:
  - Basic: ε_total = Σεᵢ
  - Advanced: tighter bounds using√k factor

### Sensitivity Analyzer
- Computes L0, L1, L2 sensitivities empirically
- Compares query outputs on neighboring datasets
- Validates theoretical bounds

## Verification Harness

### Property Gates
- **P1 Epsilon Budget**: Total loss never exceeds allocated budget
- **P2 Composition**: Basic composition theorem holds (ε_total = Σεᵢ)
- **P3 Advanced Composition**: Advanced bound is tighter than basic
- **P4 Sensitivity**: Computed sensitivity matches theoretical expectation
- **P5 Monotonicity**: More queries → more privacy loss (never less)

### Mutation Gates
- **M1 Broken Accountant**: Simulates accountant that ignores budget
- **M2 Broken Composition**: Simulates composition returning wrong value

## CLI
- `diffprivlab demo`: Run demonstration
- `diffprivlab verify --seed N --trials T`: Run verification harness
