import json

import pytest

from urltriage.cli import main, read_url_file


def test_read_url_file(tmp_path):
    f = tmp_path / "urls.txt"
    f.write_text("# 주석\n\nhttps://a.example/#frag\n  b.example  \n", encoding="utf-8")
    assert read_url_file(f) == ["https://a.example/#frag", "b.example"]


def test_offline_json_report(tmp_path, capsys):
    out = tmp_path / "r" / "report.json"
    code = main(["-u", "https://google.com", "-u", "http://g00gle-login.tk/verify", "-u", "::bad::",
                 "--offline", "--json", str(out), "--summary-only", "--no-color"])
    assert code == 0
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["options"]["offline"] is True
    by_input = {r["input"]: r for r in data["results"]}
    assert by_input["https://google.com"]["grade"] == "Low"
    assert by_input["http://g00gle-login.tk/verify"]["grade"] in ("High", "Critical")
    assert by_input["http://g00gle-login.tk/verify"]["contributions"]["typosquat"] > 0
    assert by_input["::bad::"]["error"]
    assert "피싱 위험도 요약" in capsys.readouterr().out


def test_fail_on_exit_code():
    assert main(["-u", "paypa1.com", "--offline", "--summary-only", "--fail-on", "high"]) == 2
    assert main(["-u", "google.com", "--offline", "--summary-only", "--fail-on", "high"]) == 0


def test_requires_input():
    with pytest.raises(SystemExit) as e:
        main([])
    assert e.value.code == 2
