/*
 * Investigation built-in YARA rules (starter set).
 * Web shells, credential dumpers, C2 frameworks and ransom notes, based on well-known tool strings.
 * meta.severity: info|low|medium|high|critical   meta.mitre: comma-separated ATT&CK ids
 */

rule INV_Webshell_PHP_Generic
{
    meta:
        description = "PHP web shell: PHP code combining code evaluation / command execution primitives"
        severity = "high"
        mitre = "T1505.003"
    strings:
        $php = "<?php" nocase
        $f1 = "eval(" nocase
        $f2 = "base64_decode(" nocase
        $f3 = "system(" nocase
        $f4 = "shell_exec(" nocase
        $f5 = "passthru(" nocase
        $f6 = "assert(" nocase
        $f7 = "proc_open(" nocase
        $in1 = "$_POST" nocase
        $in2 = "$_GET" nocase
        $in3 = "$_REQUEST" nocase
    condition:
        $php and 2 of ($f*) and any of ($in*) and filesize < 2MB
}

rule INV_Webshell_ASPX_Generic
{
    meta:
        description = "ASP.NET web shell: page that starts processes or evaluates code from request input"
        severity = "high"
        mitre = "T1505.003"
    strings:
        $page = "<%@ Page" nocase
        $p1 = "Process.Start" nocase
        $p2 = "cmd.exe" nocase
        $p3 = "eval(" nocase
        $in = "Request.Form" nocase
        $in2 = "Request.QueryString" nocase
        $in3 = "Request[" nocase
    condition:
        $page and any of ($p*) and any of ($in*) and filesize < 2MB
}

rule INV_Webshell_JSP_Generic
{
    meta:
        description = "JSP web shell: Runtime.exec with request input"
        severity = "high"
        mitre = "T1505.003"
    strings:
        $exec = "Runtime.getRuntime().exec" nocase
        $in = "request.getParameter" nocase
    condition:
        $exec and $in and filesize < 2MB
}

rule INV_Mimikatz_Strings
{
    meta:
        description = "Mimikatz credential dumping tool strings"
        severity = "critical"
        mitre = "T1003.001"
    strings:
        $a = "sekurlsa::logonpasswords" ascii wide nocase
        $b = "gentilkiwi" ascii wide nocase
        $c = "mimikatz" ascii wide nocase
        $d = "lsadump::sam" ascii wide nocase
        $e = "kerberos::golden" ascii wide nocase
    condition:
        2 of them
}

rule INV_CobaltStrike_Beacon_Strings
{
    meta:
        description = "Cobalt Strike beacon / loader strings"
        severity = "critical"
        mitre = "T1071.001,T1055"
    strings:
        $fmt = "%s.4%08x%08x%08x%08x%08x.%08x%08x%08x%08x%08x%08x%08x.%08x%08x%08x%08x%08x%08x%08x.%08x%08x%08x%08x%08x%08x%08x.%x%x.%s" ascii
        $b1 = "beacon.dll" ascii wide nocase
        $b2 = "beacon.x64.dll" ascii wide nocase
        $rl = "ReflectiveLoader" ascii
        $pipe = "\\\\.\\pipe\\MSSE-" ascii wide
    condition:
        $fmt or ($rl and any of ($b*)) or $pipe
}

rule INV_PowerShell_Download_Cradle
{
    meta:
        description = "Script containing a PowerShell download-and-execute cradle"
        severity = "high"
        mitre = "T1059.001,T1105"
    strings:
        $iex = /(^|[^\w-])(iex|invoke-expression)([^\w-]|$)/ ascii wide nocase
        $dl1 = "DownloadString" ascii wide nocase
        $dl2 = "DownloadData" ascii wide nocase
        $dl3 = "Net.WebClient" ascii wide nocase
        $pipe = /(iwr|invoke-webrequest|irm|invoke-restmethod)[^\r\n|]{0,400}\|\s*(iex|invoke-expression)/ ascii wide nocase
        $enc = /(^|\s)-e(nc|ncodedcommand)?\s+[A-Za-z0-9+\/=]{16,}/ ascii wide nocase
    condition:
        filesize < 5MB and not (filepath matches /(^|[\\\/])appdata[\\\/]roaming[\\\/]microsoft[\\\/]windows[\\\/]powershell[\\\/]psreadline[\\\/][^\\\/]*_history\.txt$/i) and
        (($iex and any of ($dl*)) or $pipe or ($enc and any of ($dl*)))
}

rule INV_PowerShell_Download_Cradle_History
{
    meta:
        description = "PowerShell history (PSReadLine) containing a download-and-execute cradle"
        severity = "low"
        mitre = "T1059.001,T1105"
    strings:
        $iex = /(^|[^\w-])(iex|invoke-expression)([^\w-]|$)/ ascii wide nocase
        $dl1 = "DownloadString" ascii wide nocase
        $dl2 = "DownloadData" ascii wide nocase
        $dl3 = "Net.WebClient" ascii wide nocase
        $pipe = /(iwr|invoke-webrequest|irm|invoke-restmethod)[^\r\n|]{0,400}\|\s*(iex|invoke-expression)/ ascii wide nocase
        $enc = /(^|\s)-e(nc|ncodedcommand)?\s+[A-Za-z0-9+\/=]{16,}/ ascii wide nocase
    condition:
        filesize < 5MB and filepath matches /(^|[\\\/])appdata[\\\/]roaming[\\\/]microsoft[\\\/]windows[\\\/]powershell[\\\/]psreadline[\\\/][^\\\/]*_history\.txt$/i and
        (($iex and any of ($dl*)) or $pipe or ($enc and any of ($dl*)))
}

rule INV_CobaltStrike_Beacon_Config
{
    meta:
        description = "Cobalt Strike beacon configuration block (plain or single-byte XOR 0x2e / 0x69)"
        severity = "critical"
        mitre = "T1071.001,T1055"
    strings:
        $plain = { 00 01 00 01 00 02 ?? ?? 00 02 00 01 00 02 ?? ?? 00 03 00 02 00 04 ?? ?? }
        $xor2e = { 2E 2F 2E 2F 2E 2C ?? ?? 2E 2C 2E 2F 2E 2C ?? ?? 2E 2D 2E 2C 2E 2A ?? ?? }
        $xor69 = { 69 68 69 68 69 6B ?? ?? 69 6B 69 68 69 6B ?? ?? 69 6A 69 6B 69 6D ?? ?? }
    condition:
        any of them
}

rule INV_Sliver_Implant
{
    meta:
        description = "Sliver implant: Go package paths of the Sliver C2 framework"
        severity = "critical"
        mitre = "T1071.001,T1105"
    strings:
        $a = "github.com/bishopfox/sliver/" ascii
        $b = "sliverpb" ascii
        $c = "implant/sliver" ascii
    condition:
        $a and ($b or $c)
}

rule INV_Metasploit_Stager
{
    meta:
        description = "Metasploit Windows stager shellcode (block_api) or Meterpreter server DLL markers"
        severity = "critical"
        mitre = "T1055,T1059"
    strings:
        $x86 = { FC E8 82 00 00 00 60 89 E5 31 C0 64 8B 50 30 8B 52 0C 8B 52 14 }
        $x64 = { FC 48 83 E4 F0 E8 ?? 00 00 00 41 51 41 50 52 51 56 48 31 D2 }
        $met = "metsrv.dll" ascii wide nocase
        $rl = "ReflectiveLoader" ascii
    condition:
        $x86 or $x64 or ($met and $rl)
}

rule INV_Webshell_ChinaChopper
{
    meta:
        description = "China Chopper one-line web shell (eval of a request parameter)"
        severity = "critical"
        mitre = "T1505.003"
    strings:
        $asp = /eval\s*\(?\s*request\s*\(\s*["'][^"']{1,32}["']\s*\)/ nocase
        $php = /@?eval\s*\(\s*\$_(POST|REQUEST|GET)\s*\[\s*["'][^"']{1,32}["']\s*\]\s*\)/ nocase
        $aspx = /eval\s*\(\s*request\.item\s*\[\s*["'][^"']{1,32}["']\s*\]/ nocase
    condition:
        any of them and filesize < 1MB
}

rule INV_Webshell_b374k
{
    meta:
        description = "b374k PHP web shell"
        severity = "critical"
        mitre = "T1505.003"
    strings:
        $php = "<?php" nocase
        $name = "b374k" nocase
        $sig = "Jayalah Indonesiaku" nocase
        $x1 = "gzinflate(base64_decode(" nocase
        $x2 = "shell_exec(" nocase
    condition:
        $php and $name and ($sig or any of ($x*)) and filesize < 2MB
}

rule INV_LaZagne
{
    meta:
        description = "LaZagne credential recovery tool"
        severity = "high"
        mitre = "T1555,T1552"
    strings:
        $a = "lazagne" ascii wide nocase
        $b = "AlessandroZ" ascii wide nocase
        $c = "lazagne.softwares" ascii wide nocase
        $d = "The LaZagne Project" ascii wide nocase
    condition:
        $a and ($b or $c or $d)
}

rule INV_Rubeus
{
    meta:
        description = "Rubeus Kerberos abuse tool strings"
        severity = "high"
        mitre = "T1558.003,T1550.003"
    strings:
        $a = "Rubeus" ascii wide
        $b = "asktgt" ascii wide nocase
        $c = "kerberoast" ascii wide nocase
        $d = "s4u" ascii wide nocase
        $e = "/ptt" ascii wide nocase
    condition:
        $a and 2 of ($b, $c, $d, $e)
}

rule INV_SharpHound
{
    meta:
        description = "SharpHound BloodHound collector strings"
        severity = "high"
        mitre = "T1087.002,T1069.002,T1482"
    strings:
        $a = "SharpHound" ascii wide
        $b = "BloodHound" ascii wide nocase
        $c = "CollectionMethod" ascii wide nocase
        $d = "DCOnly" ascii wide
        $e = "LoggedOn" ascii wide
    condition:
        $a and 2 of ($b, $c, $d, $e)
}

rule INV_Seatbelt
{
    meta:
        description = "Seatbelt host survey tool strings"
        severity = "high"
        mitre = "T1082,T1518"
    strings:
        $a = "Seatbelt" ascii wide
        $b = "GhostPack" ascii wide nocase
        $c = "-group=all" ascii wide nocase
        $d = "Completed collection in" ascii wide
    condition:
        $a and ($b or $c or $d)
}

rule INV_Ransom_Note_Patterns
{
    meta:
        description = "Ransom note: states that files are encrypted and points to payment or a decryptor"
        severity = "critical"
        mitre = "T1486"
    strings:
        $e1 = "your files have been encrypted" ascii wide nocase
        $e2 = "your files are encrypted" ascii wide nocase
        $e3 = "all your files have been" ascii wide nocase
        $e4 = "your network has been breached" ascii wide nocase
        $p1 = "bitcoin" ascii wide nocase
        $p2 = ".onion" ascii wide nocase
        $p3 = "decryptor" ascii wide nocase
        $p4 = "decryption key" ascii wide nocase
        $p5 = "private key" ascii wide nocase
    condition:
        any of ($e*) and any of ($p*) and filesize < 200KB
}

rule INV_Ransom_Note_Generic
{
    meta:
        description = "Ransom note: payment and decryption instructions with a Tor address"
        severity = "critical"
        mitre = "T1486"
    strings:
        $btc = "bitcoin" ascii wide nocase
        $d1 = "decrypt" ascii wide nocase
        $d2 = "your files" ascii wide nocase
        $tor = ".onion" ascii wide nocase
    condition:
        $tor and ($btc or any of ($d*)) and filesize < 1MB
}
