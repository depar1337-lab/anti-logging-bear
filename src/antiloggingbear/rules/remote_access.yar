// Anti-Logging Bear by Priest

rule ALB_Known_RAT_Names
{
    meta:
        title = "Program contains the name of a known remote-access trojan"
        severity = "high"
    strings:
        $r1 = "AsyncRAT" ascii wide nocase
        $r2 = "njRAT" ascii wide nocase
        $r3 = "DcRat" ascii wide
        $r4 = "Remcos" ascii wide
        $r5 = "NanoCore" ascii wide nocase
        $r6 = "DarkComet" ascii wide nocase
        $r7 = "XWorm" ascii wide
        $r8 = "QuasarRAT" ascii wide nocase
        $r9 = "VenomRAT" ascii wide nocase
    condition:
        uint16(0) == 0x5A4D and any of them
}

rule ALB_Reverse_Shell
{
    meta:
        title = "Opens a remote command shell for someone else"
        severity = "critical"
    strings:
        $ps1 = "New-Object System.Net.Sockets.TCPClient" ascii wide nocase
        $ps2 = "GetStream()" ascii wide nocase
        $ps3 = "iex" ascii wide nocase
        $py1 = "socket.socket(" ascii
        $py2 = "subprocess.call([\"/bin/sh\"" ascii
        $py3 = "os.dup2(" ascii
        $nc = /nc(\.exe)? -e (cmd|\/bin\/sh)/ ascii nocase
    condition:
        all of ($ps*) or ($py1 and $py3) or $py2 or $nc
}

rule ALB_PyInstaller_Bundle
{
    meta:
        title = "Bundled Python program (its code is compressed, so Barry's checks are limited)"
        severity = "low"
    strings:
        $a = "pyi-runtime-tmpdir" ascii
        $b = "_MEIPASS" ascii
        $c = "PyInstaller" ascii
    condition:
        uint16(0) == 0x5A4D and 2 of them
}

rule ALB_Test_Signature
{
    meta:
        title = "Antivirus test file (EICAR) - harmless, but antivirus treats it as a virus"
        severity = "critical"
    strings:
        $t = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE" ascii
    condition:
        $t
}
