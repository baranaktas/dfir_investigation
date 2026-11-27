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
        $dl1 = "DownloadString(" ascii wide nocase
        $dl2 = "DownloadFile(" ascii wide nocase
        $dl3 = "Invoke-WebRequest" ascii wide nocase
        $ex1 = "IEX" ascii wide
        $ex2 = "Invoke-Expression" ascii wide nocase
        $ex3 = "FromBase64String" ascii wide nocase
    condition:
        any of ($dl*) and any of ($ex*) and filesize < 5MB
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
