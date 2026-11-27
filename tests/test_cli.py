import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FIXTURES = ROOT / "tests" / "fixtures" / "evtx"


def cli(*args, home):
    env = dict(os.environ, INVESTIGATION_HOME=str(home), PYTHONPATH=str(ROOT))
    return subprocess.run([sys.executable, "-m", "investigation", *args], capture_output=True, text=True,
                          env=env, cwd=str(ROOT), timeout=120)


def test_analyze_cli(tmp_path):
    out = tmp_path / "out"
    p = cli("analyze", str(FIXTURES), "-o", str(out), "--no-install", "--case", "C1", home=tmp_path / "h")
    assert p.returncode == 0, p.stderr
    assert "report.html" in p.stdout
    assert "critical" in p.stdout.lower()
    assert json.loads((out / "findings.json").read_text())["case"]["case_id"] == "C1"


def test_missing_input_exit_2(tmp_path):
    p = cli("analyze", str(tmp_path / "nope"), "--no-install", home=tmp_path / "h")
    assert p.returncode == 2
    assert "Traceback" not in p.stderr
    assert "nope" in p.stderr


def test_nonempty_output_exit_2(tmp_path):
    out = tmp_path / "out"
    out.mkdir()
    (out / "x").write_text("x")
    p = cli("analyze", str(FIXTURES), "-o", str(out), "--no-install", home=tmp_path / "h")
    assert p.returncode == 2
    assert "--force" in p.stderr
    assert "Traceback" not in p.stderr


def test_doctor_lists_modules(tmp_path):
    home = tmp_path / "h"
    (home / "modules").mkdir(parents=True)
    (home / "modules" / "bad.py").write_text("raise RuntimeError('boom')\n")
    p = cli("doctor", home=home)
    for text in ("evtx", "builtin_rules", "html_report", "[OK]", "bad.py", "boom"):
        assert text in p.stdout, text


def test_doctor_json(tmp_path):
    p = cli("doctor", "--json", home=tmp_path / "h")
    data = json.loads(p.stdout)
    assert "evtx" in data["preflight"]["results"]


def test_modules_list_and_info(tmp_path):
    p = cli("modules", "list", home=tmp_path / "h")
    assert p.returncode == 0
    assert "evtx" in p.stdout and "directory" in p.stdout
    p = cli("modules", "list", "--type", "output", home=tmp_path / "h")
    assert "html_report" in p.stdout and "evtx" not in p.stdout
    p = cli("modules", "info", "evtx", home=tmp_path / "h")
    assert "dissect.eventlog" in p.stdout
    p = cli("modules", "info", "nope", home=tmp_path / "h")
    assert p.returncode == 2


def test_profiles_list_and_show(tmp_path):
    p = cli("profiles", "list", home=tmp_path / "h")
    assert "full" in p.stdout and "triage" in p.stdout
    p = cli("profiles", "show", "full", home=tmp_path / "h")
    out = p.stdout
    assert out.index("directory") < out.index("evtx") < out.index("builtin_rules") < out.index("html_report")


def test_run_single_module(tmp_path):
    out = tmp_path / "o"
    p = cli("run", "evtx", str(FIXTURES), "-o", str(out), "--no-install", home=tmp_path / "h")
    assert p.returncode == 0, p.stderr
    assert (out / "timeline.csv").is_file()
    assert json.loads((out / "findings.json").read_text())["findings"] == []


def test_collect_all_and_only_conflict(tmp_path):
    p = cli("collect", "--all", "--only", "live", home=tmp_path / "h")
    assert p.returncode == 2
    assert "Traceback" not in p.stderr


def test_collect_only_unknown_name(monkeypatch, capsys):
    from investigation import cli as cli_mod
    assert cli_mod.main(["collect", "--only", "nonsense"]) == 2
    err = capsys.readouterr().err
    assert "nonsense" in err and "live" in err and "processes" in err


def _fake_collect(monkeypatch, calls):
    from investigation import cli as cli_mod
    from investigation.core.collect import CollectResult
    from investigation.modules.collectors.volumes import Volume

    def fake(selection, **kw):
        calls.append((selection, kw))
        return CollectResult(root=Path("pkg"), manifest={"status": "complete", "modules": []}, exit_code=0)

    monkeypatch.setattr(cli_mod, "collect", fake)
    monkeypatch.setattr(cli_mod, "list_volumes", lambda: [Volume("C:", "NTFS", 1, "W", True),
                                                          Volume("D:", "NTFS", 1, "", False)])
    return cli_mod


def test_collect_non_tty_uses_defaults(monkeypatch, tmp_path):
    calls = []
    cli_mod = _fake_collect(monkeypatch, calls)
    monkeypatch.setattr(sys.stdin, "isatty", lambda: False)
    assert cli_mod.main(["collect", "-o", str(tmp_path), "--case", "X"]) == 0
    selection, kw = calls[0]
    assert selection is None
    assert kw["options"] == {"drives": ["C"]}
    assert kw["case_id"] == "X" and kw["confirm"]("anything") is False


def test_collect_drives_flag_validated(monkeypatch, capsys):
    calls = []
    cli_mod = _fake_collect(monkeypatch, calls)
    assert cli_mod.main(["collect", "--drives", "Z"]) == 2
    assert "C, D" in capsys.readouterr().err
    assert cli_mod.main(["collect", "--drives", "c:,D", "--all"]) == 0
    assert calls[0][1]["options"] == {"drives": ["C", "D"]}
    assert calls[0][1]["confirm"]("x") is True


def test_cli_disk_image_flag_adds_disk(monkeypatch, tmp_path):
    calls = []
    cli_mod = _fake_collect(monkeypatch, calls)
    monkeypatch.setattr(sys.stdin, "isatty", lambda: False)
    assert cli_mod.main(["collect", "--only", "live", "--disk-image", "-o", str(tmp_path)]) == 0
    assert calls[0][0] == ["live", "disk"]
    assert cli_mod.main(["collect", "--disk-image", "-o", str(tmp_path)]) == 0
    assert calls[1][0] == ["live", "files", "disk"]


def test_all_excludes_disk(monkeypatch, tmp_path):
    calls = []
    cli_mod = _fake_collect(monkeypatch, calls)
    assert cli_mod.main(["collect", "--all", "-o", str(tmp_path)]) == 0
    assert "disk" not in calls[0][0]
    assert cli_mod.main(["collect", "--all", "--disk-image", "-o", str(tmp_path)]) == 0
    assert "disk" in calls[1][0]


def test_image_drives_option_passed(monkeypatch):
    calls = []
    cli_mod = _fake_collect(monkeypatch, calls)
    monkeypatch.setattr(cli_mod, "list_volumes", lambda: [__import__("types").SimpleNamespace(letter=l, is_system=l == "C:") for l in ("C:", "T:")])
    assert cli_mod.main(["collect", "--only", "disk", "--drives", "C", "--image-drives", "t"]) == 0
    assert calls[-1][1]["options"] == {"drives": ["C"], "image_drives": ["T"]}
    assert cli_mod.main(["collect", "--only", "disk", "--image-drives", "Z"]) == 2
