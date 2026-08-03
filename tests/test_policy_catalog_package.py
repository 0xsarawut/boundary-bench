import boundarybench.policy_catalog


def test_package_imports():
    assert "compile_policy_variant" in boundarybench.policy_catalog.__all__
