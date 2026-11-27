from datetime import datetime, timedelta, timezone

import pytest

from investigation.core.attack import tactics_for
from investigation.core.models import Event
from investigation.core.requirements import Context
from investigation.core.store import EventStore
from investigation.modules.detections.builtin import BuiltinRules, load_rules

T0 = datetime(2024, 5, 1, 12, 0, 0, tzinfo=timezone.utc)
SYSMON = "Microsoft-Windows-Sysmon/Operational"
RCM = "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational"
BITS = "Microsoft-Windows-Bits-Client/Operational"
TELEMETRY = "Microsoft-Windows-Application-Experience/Program-Telemetry"
PCA = "Microsoft-Windows-Application-Experience/Program-Compatibility-Assistant"


@pytest.fixture(autouse=True)
def isolated_home(monkeypatch, tmp_path):
    monkeypatch.setenv("INVESTIGATION_HOME", str(tmp_path / "home"))


def ev(seconds=0, **fields):
    fields.setdefault("Channel", "Security")
    return Event(
        timestamp=T0 + timedelta(seconds=seconds), timestamp_desc="Event Logged", artifact="evtx",
        source_file="synthetic.evtx", message=f"{fields.get('EventID')}", fields=fields,
    )


def sysmon(eid, seconds=0, **fields):
    return ev(seconds, EventID=eid, Channel=SYSMON, **fields)


def proc(parent, image, cmd):
    return sysmon(1, ParentImage=parent, Image=image, CommandLine=cmd)


def found(tmp_path, name, events):
    d = tmp_path / name
    d.mkdir()
    store = EventStore(d / "db.sqlite")
    store.add_many(events)
    return {f.rule_id for f in BuiltinRules().detect(store, Context())}


def task(name, command, args):
    xml = f"<Task><Actions><Exec><Command>{command}</Command><Arguments>{args}</Arguments></Exec></Actions></Task>"
    return ev(EventID=4702, TaskName=name, TaskContentNew=xml)


SYS32 = "C:\\Windows\\System32\\"
PS = SYS32 + "WindowsPowerShell\\v1.0\\powershell.exe"
HKU = "HKU\\S-1-5-21-1-2-3-1000"
RUN = HKU + "\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\"

CASES = {
    "INV-EVTX-037": ([ev(EventID=1149, Channel=RCM, Param1="admin", Param3="127.0.0.1")],
                     [ev(EventID=1149, Channel=RCM, Param1="admin", Param3="10.0.2.15")]),
    "INV-EVTX-038": ([ev(EventID=4624, LogonType=10, IpAddress="::1")],
                     [ev(EventID=4624, LogonType=10, IpAddress="10.1.1.5")]),
    "INV-EVTX-039": ([ev(EventID=4794, SubjectUserName="administrator")],
                     [ev(EventID=4794, Channel="Application")]),
    "INV-EVTX-040": ([ev(EventID=4719, AuditPolicyChanges="%%8449, %%8451")],
                     [ev(EventID=4719, AuditPolicyChanges="%%8448")]),
    "INV-EVTX-041": ([ev(EventID=5136, ObjectClass="user", AttributeLDAPDisplayName="servicePrincipalName")],
                     [ev(EventID=5136, ObjectClass="computer", AttributeLDAPDisplayName="servicePrincipalName")]),
    "INV-EVTX-042": ([ev(EventID=5136, ObjectClass="computer",
                         AttributeLDAPDisplayName="msDS-AllowedToActOnBehalfOfOtherIdentity")],
                     [ev(EventID=5136, ObjectClass="user", AttributeLDAPDisplayName="description")]),
    "INV-EVTX-043": ([ev(EventID=5136, ObjectClass="groupPolicyContainer", AttributeLDAPDisplayName="versionNumber")],
                     [ev(EventID=5136, ObjectClass="user", AttributeLDAPDisplayName="versionNumber")]),
    "INV-EVTX-044": ([task("\\LMST", "cmd.exe", "/c echo x &gt; c:\\users\\public\\out.txt")],
                     [task("\\Microsoft\\Windows\\SoftwareProtectionPlatform\\SvcRestartTask", "cmd.exe", "/c x"),
                      task("\\Vendor Updater", "C:\\Program Files\\Vendor\\update.exe", "/silent")]),
    "INV-EVTX-045": ([ev(EventID=59, Channel=BITS, name="backdoor", url="C:\\Windows\\system32\\cmd.exe")],
                     [ev(EventID=59, Channel=BITS, name="Font Download", url="https://fs.microsoft.com/fs/windows/config.json")]),
    "INV-EVTX-046": ([ev(EventID=59, Channel=BITS, name="x", url="https://a.uguu.se/Hv0bgv_Bin.7z")],
                     [ev(EventID=59, Channel=BITS, name="SetupBinary",
                         url="https://oneclient.sfx.ms/Win/Prod/20.169/OneDriveSetup.exe")]),
    "INV-EVTX-047": ([ev(EventID=325, Channel="Application", Provider_Name="ESENT",
                         Data="NTDS, 3392, , 2, C:\\Users\\bob\\Desktop\\ntds\\Active Directory\\ntds.dit, 0")],
                     [ev(EventID=325, Channel="Application", Provider_Name="ESENT",
                         Data="NTDS, 612, , 1, C:\\Windows\\NTDS\\ntds.dit, 0")]),
    "INV-EVTX-048": ([ev(i, EventID=18456, Channel="Application", Provider_Name="MSSQLSERVER", Computer="SQL1",
                         Data="sa, Reason: Password did not match") for i in range(10)],
                     [ev(i, EventID=18456, Channel="Application", Provider_Name="MSSQLSERVER", Computer="SQL1",
                         Data="sa, Reason: Password did not match") for i in range(3)]),
    "INV-EVTX-049": ([ev(EventID=15457, Channel="Application", Provider_Name="MSSQLSERVER",
                         Data="xp_cmdshell, 0, 1")],
                     [ev(EventID=15457, Channel="Application", Provider_Name="MSSQLSERVER",
                         Data="show advanced options, 0, 1")]),
    "INV-EVTX-050a": ([proc("C:\\Program Files\\Microsoft SQL Server\\MSSQL\\Binn\\sqlservr.exe", SYS32 + "cmd.exe",
                            "cmd.exe /c whoami")],
                      [proc("C:\\Program Files\\Microsoft SQL Server\\MSSQL\\Binn\\sqlservr.exe",
                            "C:\\Program Files\\Microsoft SQL Server\\sqlceip.exe", "sqlceip.exe")]),
    "INV-EVTX-051": ([sysmon(10, SourceImage="C:\\Users\\Public\\a.exe", TargetImage=SYS32 + "notepad.exe",
                             GrantedAccess="0x1fffff", CallTrace="UNKNOWN(000001F3C35A0014)")],
                     [sysmon(10, SourceImage=SYS32 + "cmd.exe", TargetImage=SYS32 + "notepad.exe",
                             GrantedAccess="0x1fffff", CallTrace="C:\\Windows\\SYSTEM32\\ntdll.dll+9c534")]),
    "INV-EVTX-052": ([sysmon(10, SourceImage="C:\\Users\\bob\\AppData\\Local\\Temp\\x\\inj.exe",
                             TargetImage="C:\\Program Files\\App\\app.exe", GrantedAccess="0x147a")],
                     [sysmon(10, SourceImage="C:\\Program Files\\App\\agent.exe",
                             TargetImage="C:\\Program Files\\App\\app.exe", GrantedAccess="0x147a")]),
    "INV-EVTX-053": ([sysmon(8, SourceImage="\\\\vboxsrv\\HTools\\m.exe", TargetImage="C:\\Windows\\explorer.exe")],
                     [sysmon(8, SourceImage=SYS32 + "csrss.exe", TargetImage=SYS32 + "svchost.exe")]),
    "INV-EVTX-054": ([sysmon(8, SourceImage=SYS32 + "rundll32.exe", TargetImage=SYS32 + "lsass.exe")],
                     [sysmon(8, SourceImage=SYS32 + "csrss.exe", TargetImage=SYS32 + "svchost.exe")]),
    "INV-EVTX-055": ([sysmon(10, i, SourceImage="D:\\m.exe", TargetImage=f"C:\\p{i}.exe", GrantedAccess="0x1410")
                      for i in range(10)],
                     [sysmon(10, i, SourceImage=SYS32 + "taskmgr.exe", TargetImage=f"C:\\p{i}.exe",
                             GrantedAccess="0x1410") for i in range(10)]),
    "INV-EVTX-056": ([ev(EventID=4703, ProcessName="C:\\Users\\bob\\Desktop\\x64\\mimikatz.exe",
                         EnabledPrivilegeList="SeDebugPrivilege")],
                     [ev(EventID=4703, ProcessName=SYS32 + "svchost.exe", EnabledPrivilegeList="SeDebugPrivilege")]),
    "INV-EVTX-057": ([sysmon(13, Image="C:\\Users\\bob\\AppData\\Roaming\\NvSmart.exe", TargetObject=RUN + "360v",
                             Details="C:\\Users\\bob\\AppData\\Roaming\\svchost.exe")],
                     [sysmon(13, Image="C:\\Program Files\\App\\setup.exe", TargetObject=RUN + "App",
                             Details="\"C:\\Program Files\\App\\app.exe\" /background")]),
    "INV-EVTX-058": ([sysmon(13, Image=SYS32 + "reg.exe", Details=SYS32 + "cmd.exe",
                             TargetObject=HKU + "_Classes\\ms-settings\\shell\\open\\command\\(Default)")],
                     [sysmon(13, Image="C:\\Program Files\\App\\app.exe", Details="app.exe \"%1\"",
                             TargetObject=HKU + "_Classes\\AppFile\\shell\\open\\command\\(Default)")]),
    "INV-EVTX-059": ([sysmon(13, Image=SYS32 + "reg.exe", Details="DWORD (0x00000000)",
                             TargetObject="HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\policies\\system\\EnableLUA")],
                     [sysmon(13, Image=SYS32 + "reg.exe", Details="DWORD (0x00000001)",
                             TargetObject="HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\policies\\system\\EnableLUA")]),
    "INV-EVTX-060a": ([proc(SYS32 + "cmd.exe", SYS32 + "reg.exe",
                            "reg add hklm\\software\\microsoft\\windows\\currentversion\\policies\\system /v EnableLUA "
                            "/t REG_DWORD /d 0x0 /f")],
                      [proc(SYS32 + "cmd.exe", SYS32 + "reg.exe",
                            "reg query hklm\\software\\microsoft\\windows\\currentversion\\policies\\system /v EnableLUA")]),
    "INV-EVTX-061": ([sysmon(13, Image=SYS32 + "reg.exe", Details="Binary Data",
                             TargetObject="HKLM\\System\\CurrentControlSet\\services\\LanmanServer\\Parameters\\NullSessionPipes")],
                     [sysmon(13, Image=SYS32 + "svchost.exe", Details="Binary Data",
                             TargetObject="HKLM\\System\\CurrentControlSet\\services\\LanmanServer\\Parameters\\Size")]),
    "INV-EVTX-062": ([sysmon(13, Image="C:\\Windows\\regedit.exe", Details="c:\\programdata\\gpo.inf",
                             TargetObject=HKU + "\\Software\\Microsoft\\IEAK\\GroupPolicy\\PendingGPOs\\Path1")],
                     [sysmon(13, Image="C:\\Windows\\regedit.exe", Details="1",
                             TargetObject=HKU + "\\Software\\Microsoft\\Internet Explorer\\Main\\Start Page")]),
    "INV-EVTX-063": ([sysmon(13, Image=SYS32 + "svchost.exe", Details="c:\\windows\\system32\\cmd.exe",
                             TargetObject="HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate\\Orchestrator"
                                          "\\UScheduler\\51999\\cmdLine")],
                     [sysmon(13, Image=SYS32 + "svchost.exe", Details="QWORD (0x01d6667a-0xac806dc2)",
                             TargetObject="HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate\\Orchestrator"
                                          "\\UScheduler\\51999\\queuedTime")]),
    "INV-EVTX-064": ([sysmon(13, Image="C:\\Users\\u\\Desktop\\poc.exe", Details="\\Registry\\Machine\\System\\X",
                             TargetObject="HKLM\\SOFTWARE\\Microsoft\\DRM\\DEMO2\\SymbolicLinkValue")],
                     [sysmon(13, Image=SYS32 + "svchost.exe", Details="\\Registry\\Machine\\System\\X",
                             TargetObject="HKLM\\SYSTEM\\Select\\SymbolicLinkValue")]),
    "INV-EVTX-065": ([sysmon(7, Image=SYS32 + "migwiz\\migwiz.exe", ImageLoaded=SYS32 + "migwiz\\CRYPTBASE.dll",
                             Signed="false")],
                     [sysmon(7, Image=SYS32 + "notepad.exe", ImageLoaded=SYS32 + "cryptbase.dll", Signed="true"),
                      sysmon(7, Image="C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
                             ImageLoaded="C:\\Program Files\\Microsoft Office\\root\\Office16\\WWLIB.DLL", Signed="true")]),
    "INV-EVTX-066": ([sysmon(7, Image=SYS32 + "wuauclt.exe", ImageLoaded="C:\\ProgramData\\Intel\\helpa.dll",
                             Signed="false")],
                     [sysmon(7, Image=SYS32 + "svchost.exe", ImageLoaded="C:\\Program Files\\Vendor\\svc.dll",
                             Signed="false")]),
    "INV-EVTX-067": ([sysmon(7, Image=SYS32 + "lsass.exe", ImageLoaded="\\\\172.16.66.254\\shared\\lsadb.dll",
                             Signed="false")],
                     [sysmon(7, Image=SYS32 + "lsass.exe", ImageLoaded=SYS32 + "msv1_0.dll", Signed="true")]),
    "INV-EVTX-068a": ([proc("C:\\Users\\Public\\test.exe", "C:\\Users\\bob\\AppData\\Roaming\\WINWORD.exe", "WINWORD.exe")],
                      [proc("C:\\Windows\\explorer.exe", "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
                            "WINWORD.EXE")]),
    "INV-EVTX-069a": ([proc("C:\\Program Files\\Internet Explorer\\iexplore.exe", SYS32 + "cmd.exe", "cmd.exe")],
                      [proc("C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe", SYS32 + "cmd.exe",
                            "cmd.exe /d /c \"C:\\host.exe\" chrome-extension://abc/ --parent-window=0")]),
    "INV-EVTX-070a": ([proc(SYS32 + "sdclt.exe", SYS32 + "cmd.exe", "\"C:\\Windows\\System32\\cmd.exe\" /c notepad.exe")],
                      [proc(SYS32 + "sdclt.exe", SYS32 + "sdclt.exe", "sdclt.exe /configure")]),
    "INV-EVTX-071a": ([proc("C:\\Python27\\python.exe", SYS32 + "wusa.exe",
                            "\"C:\\Windows\\System32\\wusa.exe\" c:\\users\\u\\appdata\\local\\temp\\s.cab "
                            "/extract:C:\\Windows\\system32\\migwiz /quiet")],
                      [proc(SYS32 + "cmd.exe", SYS32 + "wusa.exe", "wusa.exe C:\\Updates\\kb123.msu /quiet /norestart")]),
    "INV-EVTX-072a": ([proc(SYS32 + "cmd.exe", SYS32 + "rundll32.exe",
                            "\"C:\\Windows\\System32\\rundll32.exe\"  zipfldr.dll,RouteTheCall c:\\Windows\\System32\\calc.exe")],
                      [proc(SYS32 + "cmd.exe", SYS32 + "rundll32.exe",
                            "rundll32.exe shell32.dll,Control_RunDLL desk.cpl")]),
    "INV-EVTX-073a": ([proc("C:\\Windows\\explorer.exe", SYS32 + "rundll32.exe",
                            "Rundll32.exe shell32.dll,Control_RunDLL C:\\PROGRA~3\\DATAUS~1.DLL 4624665222")],
                      [proc("C:\\Windows\\explorer.exe", SYS32 + "rundll32.exe",
                            "rundll32.exe C:\\Windows\\System32\\shell32.dll,Options_RunDLL 0")]),
    "INV-EVTX-074a": ([proc(SYS32 + "cmd.exe", SYS32 + "attrib.exe", "attrib  +h nbtscan.exe")],
                      [proc(SYS32 + "cmd.exe", SYS32 + "attrib.exe", "attrib -r report.docx")]),
    "INV-EVTX-075a": ([proc(SYS32 + "winrshost.exe", SYS32 + "cmd.exe", "cmd.exe /C ipconfig")],
                      [proc(SYS32 + "svchost.exe", SYS32 + "winrshost.exe", "WinrsHost.exe -Embedding")]),
    "INV-EVTX-076a": ([proc(SYS32 + "svchost.exe", SYS32 + "mshta.exe", "C:\\Windows\\System32\\mshta.exe -Embedding")],
                      [proc("C:\\Windows\\explorer.exe", SYS32 + "mmc.exe", "\"C:\\Windows\\system32\\mmc.exe\" compmgmt.msc")]),
    "INV-EVTX-077a": ([proc(SYS32 + "services.exe", "C:\\Windows\\PSEXESVC.exe", "C:\\WINDOWS\\PSEXESVC.exe")],
                      [proc(SYS32 + "services.exe", SYS32 + "svchost.exe", "svchost.exe -k netsvcs")]),
    "INV-EVTX-078": ([sysmon(11, Image="System", TargetFilename="C:\\Windows\\PSEXESVC.exe")],
                     [sysmon(11, Image="System", TargetFilename="C:\\Shares\\docs\\report.docx")]),
    "INV-EVTX-079": ([sysmon(11, Image=PS, TargetFilename="C:\\Users\\bob\\AppData\\Roaming\\Microsoft\\Windows"
                                                          "\\Start Menu\\Programs\\Startup\\bs.ps1")],
                     [sysmon(11, Image="C:\\Program Files\\App\\setup.exe",
                             TargetFilename="C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\App.lnk")]),
    "INV-EVTX-080": ([sysmon(2, Image="C:\\Users\\bob\\Downloads\\Flash_update.exe",
                             TargetFilename="C:\\Users\\bob\\AppData\\Roaming\\NvSmart.exe")],
                     [sysmon(2, Image="C:\\Program Files\\Mozilla Firefox\\firefox.exe",
                             TargetFilename="C:\\Users\\bob\\AppData\\Roaming\\Mozilla\\cache2\\entries\\ABC")]),
    "INV-EVTX-081": ([sysmon(3, Image=SYS32 + "regsvr32.exe", DestinationIp="104.20.208.21", DestinationPort=80)],
                     [sysmon(3, Image=SYS32 + "svchost.exe", DestinationIp="104.20.208.21", DestinationPort=80)]),
    "INV-EVTX-082": ([sysmon(3, Image=PS, DestinationIp="10.0.0.1", DestinationPort=389, Initiated="true")],
                     [sysmon(3, Image=PS, DestinationIp="10.0.0.1", DestinationPort=443, Initiated="true")]),
    "INV-EVTX-083": ([sysmon(3, i, Image="System", Computer="PC1", DestinationIp=f"10.0.0.{i}", DestinationPort=445,
                             Initiated="true") for i in range(5)],
                     [sysmon(3, i, Image="System", Computer="PC1", DestinationIp="10.0.0.9", DestinationPort=445,
                             Initiated="true") for i in range(5)]),
    "INV-EVTX-084": ([sysmon(18, i, Image="System", Computer="PC1", PipeName=p)
                      for i, p in enumerate(["\\srvsvc", "\\samr", "\\lsarpc", "\\wkssvc"])],
                     [sysmon(18, i, Image="System", Computer="PC1", PipeName="\\srvsvc") for i in range(4)]),
    "INV-EVTX-085": ([sysmon(17, Image=SYS32 + "PsExec.exe", PipeName="\\svchost-PC1-8116-stdin")],
                     [sysmon(17, Image=SYS32 + "svchost.exe", PipeName="\\svchost")]),
    "INV-EVTX-086": ([sysmon(17, Image="C:\\Users\\Public\\b.exe", PipeName="\\msagent_8a")],
                     [sysmon(17, Image=SYS32 + "svchost.exe", PipeName="\\ntsvcs")]),
    "INV-EVTX-087": ([sysmon(20, Operation="Created", Type="Command Line", Name="BotConsumer23")],
                     [sysmon(20, Operation="Deleted", Type="Command Line", Name="BotConsumer23")]),
    "INV-EVTX-088": ([ev(EventID=500, Channel=TELEMETRY, FixName="InjectDll", ExePath="C:\\App\\a.exe")],
                     [ev(EventID=500, Channel=TELEMETRY, FixName="WinXPSp3VersionLie", ExePath="C:\\App\\a.exe")]),
    "INV-EVTX-089": ([ev(EventID=500, Channel=TELEMETRY, FixName="CorrectFilePaths", ExePath=SYS32 + "osk.exe")],
                     [ev(EventID=500, Channel=TELEMETRY, FixName="CorrectFilePaths", ExePath="C:\\Games\\old.exe")]),
    "INV-EVTX-090": ([ev(EventID=17, Channel=PCA, ResolverName="ControlPanelApplet",
                         ExePath="C:\\Users\\bob\\Downloads\\Invoice@0582.cpl")],
                     [ev(EventID=17, Channel=PCA, ResolverName="WrpKeyMitigation",
                         ExePath="C:\\Users\\bob\\Desktop\\procexp64.exe")]),
    "INV-EVTX-091": ([ev(EventID=4799, TargetUserName="Administrators", CallerProcessName=SYS32 + "net1.exe")],
                     [ev(EventID=4799, TargetUserName="Administrators", CallerProcessName=SYS32 + "svchost.exe")]),
    "INV-EVTX-092": ([ev(EventID=5145, SubjectUserName="backdoor", ShareName="\\\\*\\IPC$",
                         RelativeTargetName="protected_storage")],
                     [ev(EventID=5145, SubjectUserName="PC1$", ShareName="\\\\*\\IPC$",
                         RelativeTargetName="protected_storage")]),
    "INV-EVTX-093a": ([proc(PS, "C:\\Users\\bob\\AppData\\Local\\Temp\\word\\2019\\Dyxxur4gx.exe", "Dyxxur4gx.exe")],
                      [proc(PS, SYS32 + "whoami.exe", "whoami /groups")]),
    "INV-EVTX-094a": ([proc("C:\\Python27\\python.exe", SYS32 + "schtasks.exe",
                            "schtasks.exe /create /xml c:\\users\\u\\appdata\\local\\temp\\elevator.xml /tn elevator")],
                      [proc(SYS32 + "cmd.exe", SYS32 + "schtasks.exe", "schtasks /query /tn elevator")]),
}


@pytest.mark.parametrize("rule_id", sorted(CASES))
def test_rule_matches_attack_and_not_benign(tmp_path, rule_id):
    attack, benign = CASES[rule_id]
    assert rule_id in found(tmp_path, "attack", attack)
    assert rule_id not in found(tmp_path, "benign", benign)


def test_every_new_rule_has_a_case():
    new = {r.id for r in load_rules() if r.id >= "INV-EVTX-037" and r.id.startswith("INV-EVTX-")}
    covered = {i.rstrip("ab") for i in CASES}
    assert {i.rstrip("ab") for i in new} == covered


def test_new_rules_have_description_note_and_tactic():
    for r in load_rules():
        if r.id.startswith("INV-EVTX-") and r.id >= "INV-EVTX-037":
            assert r.description and r.note and r.mitre
            finding = r.finding([])
            assert "other" not in tactics_for(finding)


def test_security_4688_variant_of_process_rule(tmp_path):
    e = ev(EventID=4688, ParentProcessName=SYS32 + "sdclt.exe", NewProcessName=SYS32 + "cmd.exe",
           CommandLine="cmd.exe /c notepad.exe")
    assert "INV-EVTX-070b" in found(tmp_path, "a", [e])
