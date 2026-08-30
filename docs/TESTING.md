# Testing

## Unit Tests

| Test Class | Tests | Coverage |
|------------|-------|----------|
| TestLaplaceMechanism | 6 | Valid params, noise scale, epsilon validation |
| TestGaussianMechanism | 5 | Valid params, noise, delta validation |
| TestExponentialMechanism | 2 | Outcome selection, utility preference |
| TestBudgetAccountant | 10 | Init, add, exceed, composition, remaining |
| TestSensitivity | 3 | Sum, mean, empty datasets |
| TestVerifyHarness | 2 | Passes, deterministic |
| TestMutationGates | 2 | M1 broken accountant, M2 broken composition |

## Verification Harness

```bash
diffprivlab verify --seed 42 --trials 100
```

Expected output:
```
  P1_epsilon_budget:    PASS
  P2_composition:       PASS
  P3_advanced_composition: PASS
  P4_sensitivity:       PASS
  P5_monotonicity:      PASS
  M1_broken_accountant: DETECTED
  M2_broken_composition: DETECTED
  Overall: PASS
```

## Security Audit

- ruff: All checks passed
- bandit: 0 high/medium findings
- Zero external dependencies
- No network/subprocess/eval/file I/O
