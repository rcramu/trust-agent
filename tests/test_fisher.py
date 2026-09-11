from evaluation.run import fisher_one_sided


def test_fisher_identical_tables_not_significant():
    p = fisher_one_sided(15, 15, 15, 15)
    assert p > 0.4


def test_fisher_extreme_table_is_tiny():
    p = fisher_one_sided(30, 0, 0, 30)
    assert p < 1e-12
