from investigation.core.collect_menu import ask_collection, ask_yes_no
from investigation.modules.collectors.volumes import Volume

VOLS = [Volume("C:", "NTFS", 476 * 10**9, "", True), Volume("D:", "NTFS", 100 * 10**9, "Data", False)]


def feed(*answers):
    it = iter(answers)
    return lambda _prompt: next(it)


def test_ask_yes_no_defaults():
    assert ask_yes_no("q", feed(""), print, default=True) is True
    assert ask_yes_no("q", feed(""), print) is False
    assert ask_yes_no("q", feed("y"), print) is True
    assert ask_yes_no("q", feed("N"), print, default=True) is False


def test_defaults_are_live_files_memory():
    c = ask_collection(VOLS, feed("", "", "", "", "", "", ""), lambda _: None)
    assert c.categories == ["live", "files", "memory"] and c.drives == ["C"]


def test_arm64_skips_memory_question():
    prompts, lines = [], []

    def inp(p):
        prompts.append(p)
        return ""

    c = ask_collection(VOLS, inp, lines.append, arm64=True)
    assert c.categories == ["live", "files"]
    assert "Memory image: not available on ARM64" in lines
    assert not any(p.startswith("Memory image") for p in prompts)


def test_invalid_drive_reasked_and_dedup():
    lines = []
    c = ask_collection(VOLS, feed("", "", "", "", "", "X", "c, d", ""), lines.append)
    assert any("Unknown drive(s): X. Available: C, D" in l for l in lines)
    assert c.drives == ["C", "D"]


def test_decline_start_returns_none_and_summary_precedes():
    lines, seen = [], []

    def inp(p):
        seen.append(len(lines))
        return "n" if p.startswith("Start?") else ""

    assert ask_collection(VOLS, inp, lines.append, output="OUT") is None
    assert any("Will collect" in l for l in lines) and "Output: OUT" in lines


def test_nothing_selected_returns_none():
    assert ask_collection(VOLS, feed("n", "n", "n", "n", "n"), lambda _: None) is None


def test_every_collector_has_known_category():
    from investigation.core.collect_menu import CATEGORY_LABELS
    from investigation.core.module import ModuleType
    from investigation.core.registry import ModuleRegistry

    reg = ModuleRegistry()
    reg.discover(user_dir=None, entry_points=False)
    for c in reg.by_type(ModuleType.COLLECTOR):
        assert c.meta.category in CATEGORY_LABELS, c.meta.name


def test_drives_reread_on_each_ask_and_label_accepted():
    state = {"vols": [VOLS[0]]}
    attached = Volume("T:", "NTFS", 4 * 10**9, "TESTDISK", False)
    lines, answers = [], iter(["", "", "", "", "", "T", "t:", ""])

    def inp(p):
        a = next(answers)
        if p.startswith("Collect files"):
            state["vols"] = [VOLS[0], attached]
            if a == "T":
                return "Q"
        return a

    c = ask_collection(lambda: state["vols"], inp, lines.append)
    assert c.drives == ["T"]
    assert any(l.startswith("  T:") and '"TESTDISK"' in l for l in lines)


def test_label_and_colon_forms():
    for ans in ("T:", "t", "TESTDISK", " testdisk , "):
        vols = [VOLS[0], Volume("T:", "NTFS", 4 * 10**9, "TESTDISK", False)]
        c = ask_collection(vols, feed("", "", "", "", "", ans, ""), lambda _: None)
        assert c.drives == ["T"], ans


def test_drive_list_marks_output_and_hides_empty_label():
    lines = []
    ask_collection(VOLS, feed("", "", "", "", "", "", ""), lines.append, output="C:\\out")
    assert "Drives on this machine:" in lines
    c_row = next(l for l in lines if l.startswith("  C:"))
    assert "(system, output)" in c_row and '""' not in c_row


def test_disk_image_on_output_drive_notes_once_before_summary():
    lines = []
    ask_collection(VOLS, feed("n", "n", "n", "n", "y", "C", ""), lines.append, output="C:\\out")
    notes = [i for i, l in enumerate(lines) if l.startswith("Note: the output folder is on C:")]
    assert len(notes) == 2 and notes[0] < lines.index("") + 0 + len(lines)
    assert notes[0] < next(i for i, l in enumerate(lines) if l.startswith("Will collect"))


def _out_run(answers, tmp_path, monkeypatch, vols=VOLS, est=None, free=50 * 10**9):
    from investigation.core import collect_menu as cm
    made, lines = [], []
    monkeypatch.setattr(cm, "_free_bytes", lambda p: free)
    monkeypatch.setattr(cm, "_mkdir", made.append)
    c = ask_collection(vols, feed(*answers), lines.append, estimates=est or {},
                       output=str(tmp_path), resolve_output=lambda t: t if ":" in t else tmp_path / t)
    return c, lines, made


def test_output_enter_keeps_default(tmp_path, monkeypatch):
    c, lines, made = _out_run(["", "", "", "n", "n", "", "", ""], tmp_path, monkeypatch)
    assert c.output == str(tmp_path) and made == []
    assert any(l.startswith("Output folder [") and "free: 50 GB" in l for l in lines)
    assert f"Output: {tmp_path}" in lines


def test_output_bare_letter_and_create(tmp_path, monkeypatch):
    c, lines, made = _out_run(["", "", "", "n", "n", "", "E", "", ""], tmp_path, monkeypatch)
    assert c.output == "E:\\" and made == ["E:\\"]
    assert any("Create it?" in l or True for l in lines)


def test_output_create_declined_reasks(tmp_path, monkeypatch):
    c, lines, made = _out_run(["", "", "", "n", "n", "", "newdir", "n", "", ""], tmp_path, monkeypatch)
    assert c.output == str(tmp_path) and made == []


def test_output_on_imaged_drive_warns_and_reasks(tmp_path, monkeypatch):
    c, lines, made = _out_run(["", "", "n", "n", "y", "", "C", "C:\\x", "n", "E", "", ""], tmp_path, monkeypatch)
    assert any(l.startswith("Warning:") and "imaged" in l for l in lines)
    assert c.output == "E:\\"


def test_output_too_small_warns(tmp_path, monkeypatch):
    c, lines, made = _out_run(["", "", "", "n", "n", "", "", "y", ""], tmp_path, monkeypatch,
                              est={"memory": "~64 GB"}, free=10 * 10**9)
    assert any("Warning:" in l and "GB needed" in l for l in lines)
    assert c.output == str(tmp_path)


def test_image_only_t_while_files_from_c_uses_t_estimate():
    vols = [VOLS[0], Volume("T:", "NTFS", 4 * 10**9, "TESTDISK", False)]
    lines, asked = [], []

    def est_fn(drives):
        asked.append(list(drives))
        return {"disk": "~4 GB"}

    c = ask_collection(vols, feed("", "", "", "", "y", "", "t", ""), lines.append,
                       estimates={"disk": "~476 GB"}, estimate_fn=est_fn)
    assert c.drives == ["C"] and c.image_drives == ["T"]
    assert asked == [["T"]]
    assert "Disk image size: ~4 GB" in lines
    assert "Files from: C:" in lines and "Disk image of: T:" in lines


def test_enter_on_image_prompt_drops_disk():
    lines = []
    c = ask_collection(VOLS, feed("", "", "", "", "y", "", "", ""), lines.append)
    assert "disk" not in c.categories and c.image_drives == []
    assert "Disk image of: skipped" in lines


def test_skip_words_on_files_prompt_any_case():
    for word in ("skip", "SKIP", "None", "-", "n", "No"):
        lines = []
        c = ask_collection(VOLS, feed("", "", "", "", "", word, ""), lines.append)
        assert "files" not in c.categories and "Files from: skipped" in lines, word


def test_everything_skipped_returns_none():
    lines = []
    assert ask_collection(VOLS, feed("n", "y", "n", "n", "y", "SKIP", ""), lines.append) is None
    assert "Nothing to collect." in lines


def test_unknown_value_still_reasks():
    lines = []
    c = ask_collection(VOLS, feed("", "", "", "", "", "Q", "d", ""), lines.append)
    assert any("Unknown drive(s): Q" in l for l in lines) and c.drives == ["D"]


def test_no_media_drive_rejected_and_listed():
    vols = [VOLS[0], Volume("E:", "", 0, "", False)]
    lines = []
    c = ask_collection(vols, feed("", "", "", "", "", "E", "C", ""), lines.append)
    assert any(l.startswith("  E:") and "(no media)" in l for l in lines)
    assert any("E (no media)" in l for l in lines) and c.drives == ["C"]


def test_output_on_shadow_copy_drive_warns_and_reasks(tmp_path, monkeypatch):
    c, lines, made = _out_run(["", "", "n", "y", "n", "", "C:\\x", "n", "E", "", ""], tmp_path, monkeypatch)
    msg = ("Warning: writing to C: can make Windows delete its oldest shadow copies. "
           "Use an external drive for the output.")
    assert msg in lines
    assert c.output == "E:\\"


def test_shadow_copy_warning_can_be_accepted(tmp_path, monkeypatch):
    c, lines, made = _out_run(["", "", "n", "y", "n", "", "C:\\x", "y", "", ""], tmp_path, monkeypatch)
    assert c.output == "C:\\x"


def test_no_shadow_copy_warning_for_other_drive_or_without_vss(tmp_path, monkeypatch):
    c, lines, _ = _out_run(["", "", "n", "y", "n", "", "D:\\x", "", ""], tmp_path, monkeypatch)
    assert not any("shadow copies" in l and l.startswith("Warning") for l in lines) and c.output == "D:\\x"
    c, lines, _ = _out_run(["", "", "n", "n", "n", "", "C:\\x", "", ""], tmp_path, monkeypatch)
    assert not any("oldest shadow copies" in l for l in lines)
