import pytest

from validation.validate_all_standards import _check_build_metadata, build_parser


class _CountWriter:
    def __init__(self, count):
        self.count = count

    def read_one(self, cypher, params=None):
        assert "BuildMetadata" in cypher
        return self.count


def test_zero_nodes_fails_without_flag_and_names_the_causes():
    passed, failures, warnings = _check_build_metadata(_CountWriter(0), partial_load=False)
    assert not passed and warnings == []
    assert "older than spec 1.1" in failures[0] and "partial load" in failures[0]


def test_zero_nodes_is_a_warning_with_partial_load():
    passed, failures, warnings = _check_build_metadata(_CountWriter(0), partial_load=True)
    assert passed and failures == []
    assert "--partial-load" in warnings[0]


@pytest.mark.parametrize("partial", [False, True])
def test_one_node_passes(partial):
    assert _check_build_metadata(_CountWriter(1), partial_load=partial) == (True, [], [])


@pytest.mark.parametrize("partial", [False, True])
def test_two_nodes_fail_even_with_partial_load(partial):
    passed, failures, warnings = _check_build_metadata(_CountWriter(2), partial_load=partial)
    assert not passed and warnings == []
    assert "2 BuildMetadata nodes" in failures[0]


def test_partial_load_flag_is_opt_in():
    parser = build_parser()
    assert parser.parse_args(["--post-load"]).partial_load is False
    assert parser.parse_args(["--post-load", "--partial-load"]).partial_load is True
