rule VCEngine_Trojan_Bat_ForkBomb_Gen
{
    meta:
        display_name = "VCEngine/Trojan.Bat.ForkBomb.Gen"
        description = "Wykrywa złośliwe pętle startowe w plikach wsadowych"
    strings:
        $label = /:[a-zA-Z0-9_-]+/
        $start = /start\s+("%~nx0"|%0|%~f0)/ nocase
        $goto = /goto\s+:[a-zA-Z0-9_-]+/ nocase
    condition:
        filesize < 2KB and all of them
}

rule VCEngine_NPE_HarmTool_Enhanced
{
    meta:
        display_name = "VCEngine/Tool.Win32.NPE.Harmful"
        description = "Wykrywa Norton Power Eraser jako narzędzie niepożądane"
    strings:
        $header = "Symantec Corporation" nocase wide ascii
        $product = "Norton Power Eraser" nocase wide ascii
        $internal = "NPE.exe" nocase wide ascii
        $cert = "Symantec SHA256 TimeStamping Signer" wide
    condition:
        uint16(0) == 0x5A4D and 3 of them
}

rule VCEngine_PUP_Security_Software_Setup
{
    meta:
        display_name = "VCEngine/PUP.Security.Software.Setup"
        description = "Wykrywa instalatory oprogramowania zabezpieczającego firm trzecich"
    strings:
        $m1 = "McAfee, LLC" nocase wide ascii
        $m2 = "mclinst.exe" nocase wide ascii
        $n1 = "Symantec Corporation" nocase wide ascii
        $n2 = "NSDownloader.exe" nocase wide ascii
        $n3 = "NortonDownloadManager" nocase wide ascii
    condition:
        uint16(0) == 0x5A4D and (2 of them)
}

rule VCEngine_Exploit_Gen
{
    meta:
        display_name = "VCEngine/Exploit.Win32.Generic.DS"
        description = "Wykrywa ogólne wzorce exploitów i shellcode"
    strings:
        $ds = "DarkSword" nocase wide ascii
        $p2 = "VirtualAlloc" ascii
        $p3 = "WriteProcessMemory" ascii
        $p4 = "CreateRemoteThread" ascii
        $pay = /payload|shellcode|reverse_shell/ nocase
    condition:
        (uint16(0) == 0x5A4D or uint16(0) == 0x4B50) and 
        ($ds or (3 of ($p*)) or (all of ($pay)))
}

rule VCEngine_Suspicious_Web_Downloader
{
    meta:
        display_name = "VCEngine/Heur.Suspicious.WebDownloader"
        description = "Wykrywa podejrzane skrypty pobierające pliki z sieci"
    strings:
        $s1 = "Net.WebClient" nocase
        $s2 = "DownloadFile" nocase
        $s3 = "Invoke-Expression" nocase
        $s4 = "IEX" nocase
        $s5 = "WScript.Shell" nocase
    condition:
        3 of them
}

rule VCEngine_Heur_Double_Extension
{
    meta:
        display_name = "VCEngine/Heur.Win32.DoubleExtension"
        description = "Wykrywa podejrzane podwójne rozszerzenia (np. .pdf.exe)"
    strings:
        $s1 = ".pdf.exe" nocase
        $s2 = ".docx.exe" nocase
        $s3 = ".xlsx.exe" nocase
        $s4 = ".txt.exe" nocase
    condition:
        uint16(0) == 0x5A4D and any of them
}

rule VCEngine_Worm_AutoCopy_Behavior
{
    meta:
        display_name = "VCEngine/Worm.Win32.AutoCopy"
        description = "Wykrywa zachowania typowe dla robaków (kopiowanie do autostartu)"
    strings:
        $c1 = "copy /y" nocase
        $c2 = "AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup" nocase
        $c3 = "wscript.shell" nocase
        $c4 = "FileSystemObject" nocase
    condition:
        all of ($c1, $c2) or (all of ($c3, $c4))
}

rule VCEngine_Suspicious_PowerShell_Encoded
{
    meta:
        display_name = "VCEngine/Heur.PowerShell.EncodedCommand"
        description = "Wykrywa zakodowane komendy PowerShell"
    strings:
        $ps = "powershell" nocase
        $enc = " -enc " nocase
        $e = " -EncodedCommand " nocase
        $b64 = /([A-Za-z0-9+\/]{40,})/
    condition:
        $ps and ($enc or $e) and $b64
}

rule VCEngine_Trojan_JS_Kryptik_Heur
{
    meta:
        display_name = "VCEngine/JS.Kryptik.NH"
        description = "Wykrywa zaciemniony kod JavaScript typowy dla trojanów Kryptik"
    strings:
        $s1 = "eval(unescape(" nocase
        $s2 = "String.fromCharCode" nocase
        $s3 = "document.write(unescape(" nocase
        $h1 = /[a-zA-Z0-9]{300,}/ 
        $html = "<html>" nocase
        $js = "<script" nocase
    condition:
        (filesize < 10KB) and ($html and $js) and (any of ($s*) or $h1)
}

rule VCEngine_Trojan_HTML_FakeCaptcha_U
{
    meta:
        display_name = "VCEngine/HTML.FakeCaptcha.U"
        description = "Wykrywa fałszywe strony weryfikacji CAPTCHA używane do phishingu"
        author = "VCEngine"
    strings:
        // Słowa kluczowe na fałszywych stronach weryfikacji
        $s1 = "reCAPTCHA" nocase
        $s2 = "Verify you are human" nocase
        $s3 = "Click allow to verify" nocase
        
        // Elementy kodu udającego mechanizmy Google
        $g1 = "www.google.com/recaptcha/api.js" nocase
        $g2 = "g-recaptcha" nocase
        
        // Podejrzane skrypty przekierowujące lub kopiujące do schowka
        $p1 = "navigator.clipboard.writeText" nocase
        $p2 = "powershell -Command" nocase
        $p3 = "location.replace" nocase
    condition:
        (uint16(0) == 0x3c68 or uint16(0) == 0x3c21) and // Nagłówki HTML: <html> lub <!DO
        (any of ($s*) and any of ($g*) or any of ($p*))
}

rule VCEngine_PUP_OperaGX_A
{
    meta:
        display_name = "VCEngine/PUP.OperaGX.A"
        description = "Wykrywa instalator Opera GX jako aplikację potencjalnie niepożądaną"
    strings:
        $s1 = "Opera GX" nocase wide ascii
        $s2 = "Opera Software" nocase wide ascii
        $s3 = "OperaGXSetup.exe" nocase wide ascii
        $s4 = "Opera Installer" nocase wide ascii
    condition:
        uint16(0) == 0x5A4D and (3 of them)
}

rule VCEngine_Ransomware_Generic_A
{
    meta:
        display_name = "VCEngine/Ransomware.Win32.Generic.A"
        description = "Wykrywa typowe frazy używane w komunikatach o zaszyfrowaniu danych"
    strings:
        $s1 = "all your files have been encrypted" nocase wide ascii
        $s2 = "your documents, photos, databases and other important files" nocase wide ascii
        $s3 = "decrypt_instructions" nocase wide ascii
        $s4 = "TOR browser" nocase wide ascii
        $s5 = ".onion" nocase wide ascii
        $s6 = "unique ID" nocase wide ascii
    condition:
        uint16(0) == 0x5A4D and 3 of them
}

rule VCEngine_Spyware_Stealer_Heur
{
    meta:
        display_name = "VCEngine/Spyware.Win32.Stealer.Heur"
        description = "Wykrywa próby dostępu do wrażliwych danych przeglądarek (hasła, pliki cookies)"
    strings:
        $b1 = "Login Data" ascii // Chrome/Edge passwords
        $b2 = "Web Data" ascii
        $b3 = "Cookies" ascii
        $b4 = "\\Google\\Chrome\\User Data" nocase wide ascii
        $b5 = "\\Microsoft\\Edge\\User Data" nocase wide ascii
        $s1 = "ftp://" nocase
        $s2 = "smtp://" nocase
        $s3 = "Content-Disposition: form-data; name=\"file\"" // Próba wysłania pliku przez HTTP POST
    condition:
        uint16(0) == 0x5A4D and (2 of ($b*)) and (any of ($s*))
}

rule VCEngine_Adware_Generic_B
{
    meta:
        display_name = "VCEngine/Adware.Win32.Generic.B"
        description = "Wykrywa agresywne komponenty reklamowe i śledzące"
    strings:
        $a1 = "adware" nocase
        $a2 = "trackers" nocase
        $a3 = "offerbox" nocase
        $a4 = "open-candy" nocase
        $a5 = "installcore" nocase
        $h1 = "http://api.external-ads.com" nocase
    condition:
        uint16(0) == 0x5A4D and 2 of them
}

