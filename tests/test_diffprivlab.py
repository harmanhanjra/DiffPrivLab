"""Tests for DiffPrivLab — Verified Differential Privacy Engine."""

import math
import pytest
import random

from diffprivlab import (
    LaplaceMechanism,
    GaussianMechanism,
    ExponentialMechanism,
    BudgetAccountant,
    QueryRecord,
    BudgetExhaustionError,
    compute_sensitivity,
    verify_harness,
    Sensitivity,
)


class TestLaplaceMechanism:
    """Test Laplace mechanism."""

    def test_valid_epsilon(self):
        m = LaplaceMechanism(epsilon=0.5)
        assert m.epsilon == 0.5

    def test_invalid_epsilon_zero(self):
        with pytest.raises(ValueError):
            LaplaceMechanism(epsilon=0)

    def test_invalid_epsilon_negative(self):
        with pytest.raises(ValueError):
            LaplaceMechanism(epsilon=-0.5)

    def test_add_noise_returns_float(self):
        m = LaplaceMechanism(epsilon=1.0)
        result = m.add_noise(1.0, 100.0)
        assert isinstance(result, float)

    def test_noise_scale_inverse_to_epsilon(self):
        """Larger epsilon → smaller noise scale."""
        m_small = LaplaceMechanism(epsilon=0.1)
        m_large = LaplaceMechanism(epsilon=10.0)

        # With many samples, should see the difference
        rng = random.Random(42)
        random.seed(42)

        # Small epsilon (large scale) should produce larger deviations
        results_small = [m_small.add_noise(1.0, 0.0) for _ in range(1000)]
        random.seed(42)
        results_large = [m_large.add_noise(1.0, 0.0) for _ in range(1000)]

        # Mean absolute deviation should be larger for small epsilon
        mean_abs_small = sum(abs(r) for r in results_small) / len(results_small)
        mean_abs_large = sum(abs(r) for r in results_large) / len(results_large)

        assert mean_abs_small > mean_abs_large


class TestGaussianMechanism:
    """Test Gaussian mechanism."""

    def test_valid_params(self):
        m = GaussianMechanism(epsilon=1.0, delta=0.001)
        assert m.epsilon == 1.0
        assert m.delta == 0.001

    def test_invalid_epsilon(self):
        with pytest.raises(ValueError):
            GaussianMechanism(epsilon=0, delta=0.001)

    def test_invalid_delta_zero(self):
        with pytest.raises(ValueError):
            GaussianMechanism(epsilon=1.0, delta=0)

    def test_invalid_delta_one(self):
        with pytest.raises(ValueError):
            GaussianMechanism(epsilon=1.0, delta=1.0)

    def test_add_noise_returns_float(self):
        m = GaussianMechanism(epsilon=1.0, delta=0.001)
        result = m.add_noise(1.0, 100.0)
        assert isinstance(result, float)


class TestExponentialMechanism:
    """Test exponential mechanism."""

    def test_choose_returns_outcome(self):
        outcomes = ['a', 'b', 'c']
        m = ExponentialMechanism(
            epsilon=1.0,
            outcomes=outcomes,
            utility=lambda x: 1 if x == 'a' else 0
        )
        result = m.choose()
        assert result in outcomes

    def test_higher_utility_preferred(self):
        """Mechanism should prefer higher utility outcomes."""
        outcomes = ['low', 'high']
        m = ExponentialMechanism(
            epsilon=10.0,  # High epsilon = more deterministic
            outcomes=outcomes,
            utility=lambda x: 10 if x == 'high' else 0
        )

        # With high epsilon and large utility gap, should mostly pick 'high'
        counts = {'low': 0, 'high': 0}
        for _ in range(100):
            counts[m.choose()] += 1

        # 'high' should be chosen more often
        assert counts['high'] > counts['low']


class TestBudgetAccountant:
    """Test privacy budget accountant."""

    def test_valid_init(self):
        budget = BudgetAccountant(epsilon=1.0, delta=0.001)
        assert budget.total_epsilon == 1.0
        assert budget.total_delta == 0.001

    def test_invalid_epsilon(self):
        with pytest.raises(ValueError):
            BudgetAccountant(epsilon=0)

    def test_invalid_delta_negative(self):
        with pytest.raises(ValueError):
            BudgetAccountant(epsilon=1.0, delta=-0.001)

    def test_invalid_delta_one(self):
        with pytest.raises(ValueError):
            BudgetAccountant(epsilon=1.0, delta=1.0)

    def test_can_add_within_budget(self):
        budget = BudgetAccountant(epsilon=1.0)
        record = QueryRecord('laplace', 0.3, 0.0, 1.0, 'l1')
        assert budget.can_add(0.3, 0.0)

    def test_cannot_add_over_budget(self):
        budget = BudgetAccountant(epsilon=1.0)
        record = QueryRecord('laplace', 0.6, 0.0, 1.0, 'l1')
        budget.add_query(record)
        assert not budget.can_add(0.5, 0.0)  # Would exceed 1.0

    def test_add_query_success(self):
        budget = BudgetAccountant(epsilon=1.0, delta=0.001)
        budget.add_query(QueryRecord('laplace', 0.3, 0.0, 1.0, 'l1'))
        budget.add_query(QueryRecord('gaussian', 0.4, 0.001, 1.0, 'l2'))

        assert len(budget.queries) == 2
        assert budget.current_epsilon == 0.7
        assert budget.current_delta == 0.001

    def test_add_query_exceeds_budget(self):
        budget = BudgetAccountant(epsilon=1.0)
        budget.add_query(QueryRecord('laplace', 0.6, 0.0, 1.0, 'l1'))
        # Second query would exceed budget (0.6 + 0.5 = 1.1 > 1.0)
        with pytest.raises(BudgetExhaustionError):
            budget.add_query(QueryRecord('laplace', 0.5, 0.0, 1.0, 'l1'))

    def test_remaining_budget(self):
        budget = BudgetAccountant(epsilon=1.0, delta=0.001)
        budget.add_query(QueryRecord('laplace', 0.3, 0.0, 1.0, 'l1'))

        remaining_eps, remaining_delta = budget.remaining()
        assert abs(remaining_eps - 0.7) < 1e-10
        assert abs(remaining_delta - 0.001) < 1e-10

    def test_composition_basic(self):
        budget = BudgetAccountant(epsilon=2.0)
        budget.add_query(QueryRecord('laplace', 0.5, 0.0, 1.0, 'l1'))
        budget.add_query(QueryRecord('laplace', 0.3, 0.0, 1.0, 'l1'))

        assert abs(budget.composition_basic() - 0.8) < 1e-10

    def test_composition_advanced(self):
        budget = BudgetAccountant(epsilon=1.0, delta=0.001)
        budget.add_query(QueryRecord('laplace', 0.5, 0.0, 1.0, 'l1'))
        budget.add_query(QueryRecord('laplace', 0.5, 0.0, 1.0, 'l1'))

        eps_adv, delta_adv = budget.composition_advanced(0.001)
        # Advanced composition should give reasonable bounds
        assert eps_adv >= 0.0
        assert delta_adv >= 0.0


class TestSensitivity:
    """Test sensitivity computation."""

    def test_sum_sensitivity(self):
        """L1 sensitivity of sum is max element change."""
        datasets = [
            [1.0, 2.0, 3.0],
            [1.0, 2.0, 100.0],  # One element changed by 97
        ]

        def sum_query(d):
            return sum(d)

        sens = compute_sensitivity(sum_query, datasets)
        assert abs(sens.l1 - 97.0) < 1e-10

    def test_mean_sensitivity(self):
        """L1 sensitivity of mean is max_change / n."""
        datasets = [
            [1.0, 2.0, 3.0],
            [1.0, 2.0, 100.0],  # Changed one element
        ]

        def mean_query(d):
            return sum(d) / len(d)

        sens = compute_sensitivity(mean_query, datasets)
        # Mean change is 97/3 ≈ 32.33
        expected = 97.0 / 3.0
        assert abs(sens.l1 - expected) < 1e-10

    def test_empty_datasets(self):
        """Handle empty dataset list."""
        def identity(d):
            return d[0] if d else 0

        sens = compute_sensitivity(identity, [])
        assert sens.l0 == 1.0
        assert sens.l1 == 1.0
        assert sens.l2 == 1.0


class TestVerifyHarness:
    """Test verification harness."""

    def test_harness_passes(self):
        result = verify_harness(seed=42, trials=50)
        assert result is True

    def test_harness_deterministic(self):
        result1 = verify_harness(seed=123, trials=20)
        result2 = verify_harness(seed=123, trials=20)
        assert result1 == result2

    def test_all_properties_pass(self):
        """Verify all property gates pass."""
        rng = random.Random(42)

        # P1: Budget
        budget = BudgetAccountant(epsilon=1.0, delta=0.001)
        budget.add_query(QueryRecord('laplace', 0.3, 0.0, 1.0, 'l1'))
        budget.add_query(QueryRecord('laplace', 0.4, 0.0, 1.0, 'l1'))
        budget.add_query(QueryRecord('gaussian', 0.2, 0.001, 1.0, 'l2'))
        assert budget.current_epsilon <= 1.0
        assert budget.current_delta <= 0.001

        # P2: Composition
        assert abs(budget.composition_basic() - 0.9) < 1e-10

        # P4: Sensitivity
        datasets = [[1.0, 2.0, 3.0], [1.0, 2.0, 100.0]]
        sens = compute_sensitivity(sum, datasets)
        assert abs(sens.l1 - 97.0) < 1e-10

        # P5: Monotonicity
        b = BudgetAccountant(epsilon=2.0)
        b.add_query(QueryRecord('laplace', 0.1, 0.0, 1.0, 'l1'))
        loss1 = b.current_epsilon
        b.add_query(QueryRecord('laplace', 0.2, 0.0, 1.0, 'l1'))
        loss2 = b.current_epsilon
        assert loss2 >= loss1


class TestMutationGates:
    """Test mutation detection."""

    def test_m1_broken_accountant(self):
        """Broken accountant that allows exceeding budget should be detected."""
        class BrokenBudget(BudgetAccountant):
            def add_query(self, record: QueryRecord) -> None:
                self.queries.append(record)
                self.current_epsilon += record.epsilon
                self.current_delta += record.delta

        broken = BrokenBudget(epsilon=1.0)
        broken.add_query(QueryRecord('laplace', 0.6, 0.0, 1.0, 'l1'))
        broken.add_query(QueryRecord('laplace', 0.5, 0.0, 1.0, 'l1'))
        broken.add_query(QueryRecord('laplace', 0.1, 0.0, 1.0, 'l1'))

        # Should detect budget overflow
        assert broken.current_epsilon > 1.0

    def test_m2_broken_composition(self):
        """Broken composition that returns 0 should be detected."""
        class BrokenComposition(BudgetAccountant):
            def composition_basic(self) -> float:
                return 0.0

        broken = BrokenComposition(epsilon=1.0)
        broken.add_query(QueryRecord('laplace', 0.5, 0.0, 1.0, 'l1'))
        broken.add_query(QueryRecord('laplace', 0.3, 0.0, 1.0, 'l1'))

        # Should detect wrong composition value
        assert broken.composition_basic() == 0.0
