import sys
from pathlib import Path

import pytest

from investigation import cli, console_menu
from investigation.console_menu import run_menu
from investigation.modules.collectors.volumes import Volume

ROOT = Path(__file__).resolve().parent.parent


def drive(inputs, run_cli=None, base_dir=None, open_fn=None):
    it = iter(inputs)
    out = []

    def inp(prompt=""):
        out.append(prompt)
        try:
            return next(it)
        except StopIteration:
            raise EOFError

    rc = run_menu(input_fn=inp, print_fn=lambda *a: out.append(" ".join(map(str, a))),
                  run_cli=run_cli or (lambda argv: 0), base_dir=base_dir, open_fn=open_fn)
    return rc, "\n".join(out)


def make_pkg(base, name="INV_a b İ"):
    pkg = base / name
    pkg.mkdir()
    (pkg / "manifest.json").write_text("{}")
    return pkg


def test_main_menu_lists_options(tmp_path, monkeypatch):
    monkeypatch.setattr(console_menu, "_enable_vt", lambda: True)
    rc, text = drive(["0"], base_dir=tmp_path)
    assert rc == 0
    for s in ["EVIDENCE", "TOOLS", "1  Collect evidence", "2  Analyze", "3  Verify a package",
              "4  Environment check", "5  Update Sigma rules", "0  Exit", "Output:", "Admin:", "Host:"]:
        assert s in text
    assert "Modules" not in text
    assert console_menu.CLEAR in text


def test_analyze_builds_argv_with_full_profile(tmp_path):
    pkg = make_pkg(tmp_path)
    calls = []
    drive(["2", "1", "", "n", "", "0"], run_cli=lambda a: calls.append(a) or 0, base_dir=tmp_path)
    assert calls == [["analyze", str(pkg), "-o", str(pkg) + "_report", "--profile", "full"]]


def test_existing_output_asks_overwrite(tmp_path):
    pkg = make_pkg(tmp_path)
    out = Path(str(pkg) + "_report")
    out.mkdir()
    (out / "x").write_text("1")
    calls = []
    drive(["2", "1", "", "y", "", "0"], run_cli=lambda a: calls.append(a) or 0, base_dir=tmp_path)
    assert "--force" in calls[0]
    calls.clear()
    drive(["2", "1", "", "n", "0"], run_cli=lambda a: calls.append(a) or 0, base_dir=tmp_path)
    assert calls == []


def test_open_report_prompt(tmp_path):
    pkg = make_pkg(tmp_path)
    out = Path(str(pkg) + "_report")

    def fake(a):
        out.mkdir()
        (out / "report.html").write_text("x")
        return 0

    opened = []
    drive(["2", "1", "", "y", "", "0"], run_cli=fake, base_dir=tmp_path, open_fn=opened.append)
    assert opened == [out / "report.html"]


def test_command_error_returns_to_menu(tmp_path):
    def boom(a):
        raise RuntimeError("bad")

    rc, text = drive(["4", "", "0"], run_cli=boom, base_dir=tmp_path)
    assert rc == 0 and "error: bad" in text
    assert text.count("1  Collect evidence") == 2
    assert "Press Enter to return to the menu" in text


def test_systemexit_is_caught(tmp_path):
    def ex(a):
        raise SystemExit(2)

    rc, text = drive(["4", "", "0"], run_cli=ex, base_dir=tmp_path)
    assert rc == 0 and text.count("1  Collect evidence") == 2


def test_keyboardinterrupt_in_command_returns_to_menu(tmp_path):
    def ki(a):
        raise KeyboardInterrupt

    rc, text = drive(["4", "", "0"], run_cli=ki, base_dir=tmp_path)
    assert rc == 0 and "Interrupted" in text


def test_invalid_choices_reprompt(tmp_path):
    rc, text = drive(["x", "", "9", "0"], base_dir=tmp_path)
    assert rc == 0 and text.count("1  Collect evidence") == 4


def test_eof_exits_cleanly(tmp_path):
    rc, _ = drive([], base_dir=tmp_path)
    assert rc == 0


def test_no_packages_message(tmp_path):
    calls = []
    rc, text = drive(["3", "0", "0"], run_cli=lambda a: calls.append(a) or 0, base_dir=tmp_path)
    assert "p) Type a path" in text and "0) Back" in text
    assert calls == []


def test_type_a_path(tmp_path):
    calls = []
    target = str(tmp_path / "some" / "dir")
    drive(["3", "p", target, "", "0"], run_cli=lambda a: calls.append(a) or 0, base_dir=tmp_path)
    assert calls == [["verify", target]]


def test_other_options_argv(tmp_path):
    pkg = make_pkg(tmp_path)
    calls = []
    drive(["3", "1", "", "4", "", "5", "", "0"],
          run_cli=lambda a: calls.append(a) or 0, base_dir=tmp_path)
    assert calls == [["verify", str(pkg)], ["doctor"], ["rules", "update"]]


def test_list_packages_newest_first(tmp_path):
    a = make_pkg(tmp_path, "INV_h_20240101T000000Z")
    b = make_pkg(tmp_path, "INV_h_20250101T000000Z")
    (tmp_path / "INV_nomanifest").mkdir()
    assert console_menu.list_packages(tmp_path) == [b, a]


def test_cli_menu_subcommand_dispatches(monkeypatch):
    monkeypatch.setattr(console_menu, "run_menu", lambda: 7)
    assert cli.main(["menu"]) == 7


def test_entry_without_args_runs_menu(monkeypatch):
    sys.path.insert(0, str(ROOT / "packaging"))
    try:
        import entry
    finally:
        sys.path.pop(0)
    monkeypatch.setattr(console_menu, "run_menu", lambda: 5)
    monkeypatch.setattr(sys, "argv", ["x"])
    assert entry.run() == 5


def test_spec_requests_uac_admin():
    assert "uac_admin=True" in (ROOT / "packaging" / "investigation.spec").read_text()


def test_quoted_path_with_spaces(tmp_path):
    calls = []
    target = str(tmp_path / "some dir" / "x y")
    drive(["3", "p", f'  "{target}"  ', "", "0"], run_cli=lambda a: calls.append(a) or 0, base_dir=tmp_path)
    assert calls == [["verify", target]]


def test_relative_report_folder_under_base(tmp_path):
    pkg = make_pkg(tmp_path)
    calls = []
    drive(["2", "1", "rep", "", "0"], run_cli=lambda a: calls.append(a) or 0, base_dir=tmp_path)
    assert calls[0][3] == str(tmp_path / "rep")
    assert calls[0][1] == str(pkg)


def test_trailing_backslash_package_path(tmp_path):
    pkg = make_pkg(tmp_path)
    calls = []
    drive(["2", "p", str(pkg) + "\\", "", "", "0"], run_cli=lambda a: calls.append(a) or 0, base_dir=tmp_path)
    assert calls[0][3] == str(pkg) + "_report"


def test_ctrl_c_at_prompts_exits_cleanly(tmp_path):
    def inp(prompt=""):
        raise KeyboardInterrupt

    out = []
    assert run_menu(input_fn=inp, print_fn=out.append, run_cli=lambda a: 0, base_dir=tmp_path) == 0
    assert "Bye" in out
    seq = iter(["4", None])

    def inp2(prompt=""):
        v = next(seq)
        if v is None:
            raise KeyboardInterrupt
        return v

    assert run_menu(input_fn=inp2, print_fn=lambda *a: None, run_cli=lambda a: 0, base_dir=tmp_path) == 0


def test_stale_report_not_offered(tmp_path):
    import os
    pkg = make_pkg(tmp_path)
    out = Path(str(pkg) + "_report")
    out.mkdir()
    rep = out / "report.html"
    rep.write_text("x")
    os.utime(rep, (1, 1))
    opened = []
    rc, text = drive(["2", "1", "", "y", "", "y", "0"], run_cli=lambda a: 0, base_dir=tmp_path,
                     open_fn=opened.append)
    assert "Open report?" not in text and opened == []


def test_report_not_offered_on_failure(tmp_path):
    pkg = make_pkg(tmp_path)
    out = Path(str(pkg) + "_report")

    def fake(a):
        out.mkdir()
        (out / "report.html").write_text("x")
        return 2

    rc, text = drive(["2", "1", "", "", "0"], run_cli=fake, base_dir=tmp_path)
    assert "Open report?" not in text


VOLS = [Volume("C:", "NTFS", 476 * 10**9, "", True), Volume("D:", "NTFS", 100 * 10**9, "Data", False)]


@pytest.fixture
def x64(monkeypatch):
    monkeypatch.setattr("investigation.core.collect_menu.is_arm64", lambda: False)
    monkeypatch.setattr("investigation.core.collect_menu.runtime_estimates", lambda *a: {})
    monkeypatch.setattr("investigation.modules.collectors.volumes.list_volumes", lambda: VOLS)


def test_collect_all_defaults(tmp_path, x64):
    calls = []
    rc, text = drive(["1", "", "", "", "", "", "", "", "", "", "0"], run_cli=lambda a: calls.append(a) or 0,
                     base_dir=tmp_path)
    assert calls == [["collect", "--only", "live,files,memory", "--drives", "C", "--yes", "-o", str(tmp_path)]]
    assert "Will collect: live, files, memory" in text and f"Output: {tmp_path}" in text
    assert text.index("Will collect") < text.index("Start?")


def test_collect_custom_answers_and_drives(tmp_path, x64, monkeypatch):
    from investigation.core import collect_menu
    monkeypatch.setattr(collect_menu, "_output_letter", lambda _output: "Z")
    calls = []
    drive(["1", "n", "", "n", "y", "y", "c,d", "d", "", "", "", "0"], run_cli=lambda a: calls.append(a) or 0,
          base_dir=tmp_path)
    assert calls[0][2] == "files,vss,disk" and calls[0][4] == "C,D"
    assert calls[0][-2:] == ["--image-drives", "D"]


def test_collect_arm64_skips_memory(tmp_path, x64, monkeypatch):
    monkeypatch.setattr("investigation.core.collect_menu.is_arm64", lambda: True)
    calls = []
    rc, text = drive(["1", "", "", "", "", "", "", "", "", "0"], run_cli=lambda a: calls.append(a) or 0,
                     base_dir=tmp_path)
    assert "Memory image: not available on ARM64" in text and "Memory image (" not in text
    assert calls[0][2] == "live,files"


def test_collect_invalid_drive_reasked(tmp_path, x64):
    calls = []
    rc, text = drive(["1", "", "", "", "", "", "Z", "d", "", "", "", "0"], run_cli=lambda a: calls.append(a) or 0,
                     base_dir=tmp_path)
    assert "Unknown drive(s): Z. Available: C, D" in text
    assert calls[0][4] == "D"


def test_collect_decline_start_runs_nothing(tmp_path, x64):
    calls = []
    rc, text = drive(["1", "", "", "", "", "", "", "", "n", "0"], run_cli=lambda a: calls.append(a) or 0,
                     base_dir=tmp_path)
    assert calls == [] and rc == 0


def test_enter_prompt_after_command_then_clear(tmp_path, monkeypatch):
    monkeypatch.setattr(console_menu, "_enable_vt", lambda: True)
    rc, text = drive(["4", "", "0"], base_dir=tmp_path)
    assert text.count(console_menu.CLEAR) >= 3


def test_all_skipped_runs_no_cli(tmp_path, x64):
    calls = []
    rc, text = drive(["1", "n", "", "n", "n", "y", "skip", "", "", "0"],
                     run_cli=lambda a: calls.append(a) or 0, base_dir=tmp_path)
    assert calls == [] and "Nothing to collect." in text
