"""Unit coverage for app.services.llm_grounding (planning#140 slice 1, R2).

Pure — no DB, no HTTP, no fixtures to clean up. See that module's
docstring for the per-field rules being pinned here.

Run with:  pytest app/tests/test_llm_grounding.py
       or: python -m app.tests.test_llm_grounding
"""

from pydantic import BaseModel

from app.services.llm_grounding import Grounded, check_grounding


def test_whitespace_case_and_nfkc_normalisation_pass():
    """A quote that differs from the span only by re-flowed whitespace,
    case, and fullwidth Unicode forms must still be accepted."""
    class Fact(BaseModel):
        headline: Grounded[str]

    span = "Revenue   grew\nsignificantly  this\tquarter."
    quote = "ＲＥＶＥＮＵＥ grew significantly this quarter."  # fullwidth "REVENUE"
    fact = Fact(headline=Grounded(value="revenue grew significantly this quarter.", quote=quote))

    assert check_grounding(fact, span) == []


def test_value_not_substring_of_quote_fails():
    """A real quote paired with an invented value must fail — the value
    check is against the QUOTE, not the span."""
    class Fact(BaseModel):
        headline: Grounded[str]

    span = "Revenue grew significantly this quarter."
    fact = Fact(headline=Grounded(value="revenue collapsed", quote="Revenue grew significantly"))

    assert check_grounding(fact, span) == ["headline"]


def test_none_value_passes_regardless_of_quote():
    """`value is None` means nothing was claimed — passes even with a
    nonsense quote, because `quote` is ignored in this case."""
    class Fact(BaseModel):
        headline: Grounded[str]

    span = "Revenue grew significantly this quarter."
    fact = Fact(headline=Grounded(value=None, quote="this text does not appear anywhere in the span"))

    assert check_grounding(fact, span) == []


def test_missing_quote_fails():
    """A claimed value with no supporting quote at all (None, or empty
    string) fails."""
    class Fact(BaseModel):
        headline: Grounded[str]

    span = "Revenue grew significantly this quarter."

    fact_none = Fact(headline=Grounded(value="Revenue grew", quote=None))
    assert check_grounding(fact_none, span) == ["headline"]

    fact_empty = Fact(headline=Grounded(value="Revenue grew", quote=""))
    assert check_grounding(fact_empty, span) == ["headline"]


def test_nested_list_path_reported_as_a_b1_c():
    """Nested models and lists of models are walked — a failing field
    three levels deep, inside a list, is reported as `a.b[1].c`."""
    class Item(BaseModel):
        c: Grounded[str]

    class B(BaseModel):
        b: list[Item]

    class A(BaseModel):
        a: B

    span = "The subsidiary Example Holdings BV was founded in 2019."
    good = Item(c=Grounded(value="Example Holdings BV", quote="Example Holdings BV"))
    bad = Item(c=Grounded(value="an invented subsidiary name", quote="an invented subsidiary name"))
    instance = A(a=B(b=[good, bad]))

    assert check_grounding(instance, span) == ["a.b[1].c"]


def _run():
    tests = [
        test_whitespace_case_and_nfkc_normalisation_pass,
        test_value_not_substring_of_quote_fails,
        test_none_value_passes_regardless_of_quote,
        test_missing_quote_fails,
        test_nested_list_path_reported_as_a_b1_c,
    ]
    for fn in tests:
        fn()
        print(f"ok  {fn.__name__}")
    print("all passed")


if __name__ == "__main__":
    _run()
