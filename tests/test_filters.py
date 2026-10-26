from dns_guard.domain import domain_match
from dns_guard.filters import find_match, load_domain_list

def test_label_boundary_matching():
    assert domain_match("sub.example.com", "example.com")
    assert not domain_match("notexample.com", "example.com")

def test_load_list_ignores_comments(tmp_path):
    path = tmp_path / "list.txt"
    path.write_text("# comment\nexample.com\n\n", encoding="utf-8")
    assert load_domain_list(path) == ("example.com",)
    assert find_match("a.example.com", ("example.com",)) == "example.com"
