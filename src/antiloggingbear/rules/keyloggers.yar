// Anti-Logging Bear by Priest

rule ALB_Keylogger_Log_Tokens
{
    meta:
        title = "Formats key presses the way keyloggers do"
        severity = "high"
    strings:
        $k1 = "[BACKSPACE]" ascii wide nocase
        $k2 = "[ENTER]" ascii wide nocase
        $k3 = "[SHIFT]" ascii wide nocase
        $k4 = "[CAPSLOCK]" ascii wide nocase
        $k5 = "[TAB]" ascii wide nocase
        $k6 = "[CTRL]" ascii wide nocase
        $k7 = "[ESC]" ascii wide nocase
        $k8 = "[DEL]" ascii wide nocase
        $k9 = "[SPACE]" ascii wide nocase
        $api1 = "GetAsyncKeyState" ascii wide
        $api2 = "SetWindowsHookEx" ascii wide
        $api3 = "GetForegroundWindow" ascii wide
        $api4 = "pynput" ascii wide
    condition:
        4 of ($k*) and any of ($api*)
}

rule ALB_Keylogger_Hook_And_Upload
{
    meta:
        title = "Keyboard capture combined with mail, webhook or bot upload"
        severity = "critical"
    strings:
        $h1 = "SetWindowsHookEx" ascii wide
        $h2 = "GetAsyncKeyState" ascii wide
        $h3 = "pynput.keyboard" ascii wide
        $x1 = "discord.com/api/webhooks" ascii wide nocase
        $x2 = "discordapp.com/api/webhooks" ascii wide nocase
        $x3 = "api.telegram.org/bot" ascii wide nocase
        $x4 = "smtp.gmail.com" ascii wide nocase
        $x5 = "MAIL FROM:" ascii wide
    condition:
        any of ($h*) and any of ($x*)
}
