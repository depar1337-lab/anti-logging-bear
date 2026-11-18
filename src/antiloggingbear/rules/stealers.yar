// Anti-Logging Bear by Priest

rule ALB_Browser_Password_Stealer
{
    meta:
        title = "Collects saved browser passwords and cookies"
        severity = "critical"
    strings:
        $p1 = "\\Google\\Chrome\\User Data" ascii wide nocase
        $p2 = "\\Microsoft\\Edge\\User Data" ascii wide nocase
        $p3 = "\\BraveSoftware\\Brave-Browser" ascii wide nocase
        $p4 = "\\Opera Software\\Opera" ascii wide nocase
        $p5 = "\\Yandex\\YandexBrowser" ascii wide nocase
        $p6 = "logins.json" ascii wide
        $p7 = "key4.db" ascii wide
        $f1 = "Login Data" ascii wide
        $f2 = "Local State" ascii wide
        $d1 = "CryptUnprotectData" ascii wide
        $d2 = "encrypted_key" ascii wide
        $d3 = "os_crypt" ascii wide
    condition:
        2 of ($p*) and any of ($f*) and any of ($d*)
}

rule ALB_Discord_Token_Grabber
{
    meta:
        title = "Steals Discord login tokens"
        severity = "critical"
    strings:
        $path1 = "\\discord\\Local Storage\\leveldb" ascii wide nocase
        $path2 = "\\discordcanary\\" ascii wide nocase
        $path3 = "\\discordptb\\" ascii wide nocase
        $path4 = "\\Lightcord\\" ascii wide nocase
        $tok1 = "dQw4w9WgXcQ:" ascii wide
        $tok2 = "/api/v9/users/@me" ascii wide
        $tok3 = "encrypted_key" ascii wide
    condition:
        any of ($path*) and any of ($tok*)
}

rule ALB_Crypto_Wallet_Stealer
{
    meta:
        title = "Looks for cryptocurrency wallet files"
        severity = "high"
    strings:
        $w1 = "wallet.dat" ascii wide nocase
        $w2 = "\\Exodus\\exodus.wallet" ascii wide nocase
        $w3 = "\\Electrum\\wallets" ascii wide nocase
        $w4 = "\\Atomic\\Local Storage" ascii wide nocase
        $w5 = "nkbihfbeogaeaoehlefnkodbefgpgknn" ascii wide
        $w6 = "\\Ethereum\\keystore" ascii wide nocase
        $w7 = "\\Coinomi\\Coinomi\\wallets" ascii wide nocase
    condition:
        3 of them
}

rule ALB_Known_Stealer_Names
{
    meta:
        title = "Contains the name of a known password-stealing tool"
        severity = "high"
    strings:
        $s1 = "LummaC2" ascii wide nocase
        $s2 = "AgentTesla" ascii wide nocase
        $s3 = "BlankGrabber" ascii wide nocase
        $s4 = "Blank Grabber" ascii wide nocase
        $s5 = "Empyrean" ascii wide
        $s6 = "Luna Grabber" ascii wide nocase
        $s7 = "Hazard Token Grabber" ascii wide nocase
        $s8 = "PySilon" ascii wide nocase
        $s9 = "Creal Stealer" ascii wide nocase
        $s10 = "Doenerium" ascii wide nocase
    condition:
        any of them
}
