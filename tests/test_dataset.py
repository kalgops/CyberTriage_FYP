"""Tests for deterministic labelled scenario generation."""

from cybertriage.synthetic_dataset import NEGATIVE, POSITIVE, generate_scenarios


def test_default_dataset_has_eighty_scenarios():
    assert len(generate_scenarios()) == 80


def test_dataset_covers_all_eight_categories():
    assert {s.category for s in generate_scenarios()} == NEGATIVE | POSITIVE


def test_dataset_labels_match_category_contract():
    for scenario in generate_scenarios():
        assert scenario.label == int(scenario.category in POSITIVE)


def test_dataset_generation_is_deterministic():
    first = generate_scenarios(seed=3070)
    second = generate_scenarios(seed=3070)
    assert first == second


def test_training_partition_contains_only_normal_rows():
    training = [s for s in generate_scenarios() if s.split == "train_normal"]
    assert len(training) == 24
    assert all(s.label == 0 for s in training)
