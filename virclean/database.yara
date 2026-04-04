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
        filesize < 1KB and all of them
}

rule VCEngine_NPE_HarmTool_Enhanced
{
    meta:
        display_name = "VCEngine/Tool.Win32.NPE.Harmful"
        description = "Wykrywa Norton Power Eraser (Symantec / NortonLifeLock / Gen Digital)"
        author = "VCEngine"

    strings:
        $corp1 = "Symantec Corporation" nocase wide ascii
        $corp2 = "NortonLifeLock Inc." nocase wide ascii
        $corp3 = "Gen Digital Inc" nocase wide ascii

        $product = "Norton Power Eraser" nocase wide ascii
        $internal = "NPE.exe" nocase wide ascii fullword

        $cert1 = "Symantec SHA256 TimeStamping Signer" wide
        $cert2 = "DigiCert Trusted G4 Code Signing" wide
        $cert3 = "NortonLifeLock Code Signing" wide ascii

    condition:
        uint16(0) == 0x5A4D and 
        ($product and $internal) and 
        (any of ($corp*) or any of ($cert*))
}

rule VCEngine_PUP_Security_Software_Setup
{
    meta:
        display_name = "VCEngine/PUP.Security.Software.Setup"
        description = "Wykrywa instalatory oprogramowania zabezpieczającego firm trzecich"
    strings:
        $m1 = "McAfee, LLC" nocase wide ascii
        $m2 = "mclinst.exe" nocase wide ascii fullword
        $n1 = "Symantec Corporation" nocase wide ascii
        $n2 = "NSDownloader.exe" nocase wide ascii fullword
        $n3 = "NortonDownloadManager" nocase wide ascii
    condition:
        uint16(0) == 0x5A4D and (4 of them)
}

rule VCEngine_Exploit_Gen
{
    meta:
        display_name = "VCEngine/Exploit.Win32.Generic.DS"
        description = "Wykrywa ogólne wzorce exploitów i shellcode"
    strings:
        $ds = "DarkSword" nocase wide ascii
        $p2 = "VirtualAlloc" ascii fullword
        $p3 = "WriteProcessMemory" ascii fullword
        $p4 = "CreateRemoteThread" ascii fullword
        $pay = /payload|shellcode|reverse_shell/ nocase
    condition:
        (uint16(0) == 0x5A4D or uint16(0) == 0x4B50) and 
        ($ds and (all of ($p*)) and $pay)
}

rule VCEngine_Suspicious_Web_Downloader
{
    meta:
        display_name = "VCEngine/Heur.Suspicious.WebDownloader"
        description = "Wykrywa podejrzane skrypty pobierające pliki z sieci"
    strings:
        $s1 = "Net.WebClient" nocase fullword
        $s2 = "DownloadFile" nocase fullword
        $s3 = "Invoke-Expression" nocase fullword
        $s4 = "IEX" nocase fullword
        $s5 = "WScript.Shell" nocase fullword
    condition:
        all of them
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
        uint16(0) == 0x5A4D and (filesize < 5MB) and any of them
}

rule VCEngine_Worm_AutoCopy_Behavior
{
    meta:
        display_name = "VCEngine/Worm.Win32.AutoCopy"
        description = "Wykrywa zachowania typowe dla robaków (kopiowanie do autostartu)"
    strings:
        $c1 = "copy /y" nocase fullword
        $c2 = "AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup" nocase
        $c3 = "wscript.shell" nocase fullword
        $c4 = "FileSystemObject" nocase fullword
    condition:
        all of them
}

rule VCEngine_Suspicious_PowerShell_Encoded
{
    meta:
        display_name = "VCEngine/Heur.PowerShell.EncodedCommand"
        description = "Wykrywa zakodowane komendy PowerShell"
    strings:
        $ps = "powershell" nocase fullword
        $enc = " -enc " nocase
        $e = " -EncodedCommand " nocase
        $b64 = /([A-Za-z0-9+\/]{64,})/
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
        $h1 = /[a-zA-Z0-9]{500,}/ 
        $html = "<html>" nocase
        $js = "<script" nocase
    condition:
        (filesize < 50KB) and ($html and $js) and (all of ($s*) and $h1)
}

rule VCEngine_Trojan_HTML_FakeCaptcha_U
{
    meta:
        display_name = "VCEngine/HTML.FakeCaptcha.U"
        description = "Wykrywa fałszywe strony weryfikacji CAPTCHA używane do phishingu"
        author = "VCEngine"
    strings:
        $s1 = "reCAPTCHA" nocase
        $s2 = "Verify you are human" nocase
        $s3 = "Click allow to verify" nocase
        $g1 = "www.google.com/recaptcha/api.js" nocase
        $g2 = "g-recaptcha" nocase
        $p1 = "navigator.clipboard.writeText" nocase
        $p2 = "powershell -Command" nocase
        $p3 = "location.replace" nocase
    condition:
        (uint16(0) == 0x3c68 or uint16(0) == 0x3c21) and 
        (all of ($s*) and all of ($g*) and all of ($p*))
}

rule VCEngine_PUP_OperaGX_A
{
    meta:
        display_name = "VCEngine/PUP.OperaGX.A"
        description = "Wykrywa instalator Opera GX jako aplikację potencjalnie niepożądaną"
    strings:
        $s1 = "Opera GX" nocase wide ascii
        $s2 = "Opera Software" nocase wide ascii
        $s3 = "OperaGXSetup.exe" nocase wide ascii fullword
        $s4 = "Opera Installer" nocase wide ascii
    condition:
        uint16(0) == 0x5A4D and (all of them)
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
        $s4 = "TOR browser" nocase wide ascii fullword
        $s5 = ".onion" nocase wide ascii fullword
        $s6 = "unique ID" nocase wide ascii
    condition:
        uint16(0) == 0x5A4D and (5 of them)
}

rule VCEngine_Spyware_Stealer_Heur
{
    meta:
        display_name = "VCEngine/Spyware.Win32.Stealer.Heur"
        description = "Wykrywa próby dostępu do wrażliwych danych przeglądarek (hasła, pliki cookies)"
    strings:
        $b1 = "Login Data" ascii fullword
        $b2 = "Web Data" ascii fullword
        $b3 = "Cookies" ascii fullword
        $b4 = "\\Google\\Chrome\\User Data" nocase wide ascii
        $b5 = "\\Microsoft\\Edge\\User Data" nocase wide ascii
        $s1 = "ftp://" nocase
        $s2 = "smtp://" nocase
        $s3 = "Content-Disposition: form-data; name=\"file\"" 
    condition:
        uint16(0) == 0x5A4D and (4 of ($b*)) and (any of ($s*))
}

rule VCEngine_Adware_Generic_B
{
    meta:
        display_name = "VCEngine/Adware.Win32.Generic.B"
        description = "Wykrywa agresywne komponenty reklamowe i śledzące"
    strings:
        $a1 = "adware" nocase fullword
        $a2 = "trackers" nocase fullword
        $a3 = "offerbox" nocase fullword
        $a4 = "open-candy" nocase fullword
        $a5 = "installcore" nocase fullword
        $h1 = "http://api.external-ads.com" nocase
    condition:
        uint16(0) == 0x5A4D and (all of them)
}

rule VCEngine_Spyware_Keylogger_Gen {
    meta:
        display_name = "VCEngine/Spyware.Win32.Keylogger"
        description = "Wykryto funkcje śledzenia klawiatury (Keylogging) używane do kradzieży haseł."
    strings:
        $f1 = "SetWindowsHookEx" ascii fullword
        $f2 = "GetAsyncKeyState" ascii fullword
        $f3 = "GetForegroundWindow" ascii fullword
        $f4 = "keylog" ascii nocase fullword
    condition:
        (uint16(0) == 0x5A4D) and (all of them)
}

rule VCEngine_Spyware_ScreenCapture {
    meta:
        display_name = "VCEngine/Spyware.Win32.ScreenSpy"
        description = "Wykryto próby wykonywania zrzutów ekranu bez wiedzy użytkownika."
    strings:
        $g1 = "CreateCompatibleBitmap" ascii fullword
        $g2 = "BitBlt" ascii fullword
        $g3 = "GetDC" ascii fullword
        $g4 = "capCreateCaptureWindow" ascii fullword
    condition:
        uint16(0) == 0x5A4D and all of them
}

rule VCEngine_Infostealer_Browser_Paths {
    meta:
        display_name = "VCEngine/Stealer.Win32.BrowserData"
        description = "Wykryto próby dostępu do wrażliwych danych przeglądarek (hasła, ciasteczka, bazy SQLite)."
    strings:
        $p1 = "\\Google\\Chrome\\User Data" ascii nocase
        $p2 = "\\Opera Software\\Opera GX" ascii nocase
        $p3 = "\\Microsoft\\Edge\\User Data" ascii nocase
        $p4 = "Login Data" ascii nocase fullword
        $p5 = "Web Data" ascii nocase fullword
        $p6 = "Cookies" ascii nocase fullword
    condition:
        (uint16(0) == 0x5A4D) and (all of ($p1, $p2, $p3) and all of ($p4, $p5, $p6))
}

rule VCEngine_Infostealer_Discord_Token {
    meta:
        display_name = "VCEngine/Stealer.Win32.DiscordToken"
        description = "Wykryto próbę kradzieży tokenu autoryzacyjnego aplikacji Discord."
    strings:
        $d1 = "discordapp.com/api/v" ascii nocase
        $d2 = "Local Storage\\leveldb" ascii nocase
        $d3 = "tokens.txt" ascii nocase fullword
        $regex_token = /[a-zA-Z0-9_-]{24}\.[a-zA-Z0-9_-]{6}\.[a-zA-Z0-9_-]{27}/
    condition:
        all of ($d*) and $regex_token
}

rule VCEngine_Miner_Crypto_Gen {
    meta:
        display_name = "VCEngine/Miner.Win32.Cryptonight"
        description = "Wykryto koparkę kryptowalut obciążającą procesor i kartę graficzną."
    strings:
        $m1 = "cryptonight" ascii nocase fullword
        $m2 = "stratum+tcp://" ascii nocase
        $m3 = "xmrig" ascii nocase fullword
        $m4 = "mine.moneropool.com" ascii nocase
    condition:
        (uint16(0) == 0x5A4D) and (all of them)
}

rule VCEngine_PUP_VPNProxyMaster {
    meta:
        display_name = "VCEngine/PUP.Win32.VPNMaster.Gen"
        description = "Wykryto potencjalnie niechciane oprogramowanie (PUP) - VPN Proxy Master. Program może spowalniać system i gromadzić dane o aktywności sieciowej."
    strings:
        $s1 = "VPN Proxy Master" ascii nocase
        $s2 = "vpnmaster.com" ascii nocase
        $s3 = "VPNProxyMaster.exe" ascii nocase fullword
        $s4 = "CloudVPN" ascii nocase
        $s5 = "vpnproxy_service" ascii nocase fullword
    condition:
        (uint16(0) == 0x5A4D) and (4 of them)
}

rule VCEngine_PUP_MyCleanPC {
    meta:
        display_name = "VCEngine/PUP.Win32.MyCleanPC"
        description = "Wykryto MyClean PC - program typu Scareware, który wyolbrzymia problemy systemowe, aby wymusić zakup licencji."
    strings:
        $s1 = "MyCleanPC" ascii nocase
        $s2 = "MyCleanPC.exe" ascii nocase fullword
        $s3 = "CyberDefender" ascii nocase
        $s4 = "Your PC is infected" ascii nocase
    condition:
        (uint16(0) == 0x5A4D) and (all of them)
}

rule VCEngine_PUP_DriverPack_Notifier {
    meta:
        display_name = "VCEngine/PUP.Win32.DriverPack"
        description = "Wykryto DriverPack Solution. Program często instaluje niechciane dodatki, przeglądarki i zmienia ustawienia systemowe bez wyraźnej zgody."
    strings:
        $d1 = "DriverPack" ascii nocase
        $d2 = "drp.su" ascii nocase
        $d3 = "DriverPackNotifier.exe" ascii nocase fullword
    condition:
        (uint16(0) == 0x5A4D) and (all of them)
}

rule VCEngine_PUP_WinZip_Registry_Optimizer {
    meta:
        display_name = "VCEngine/PUP.Win32.WinZipOptimizer"
        description = "Wykryto WinZip Registry Optimizer. Program agresywnie namawia do naprawy błędów rejestru, co może być ryzykowne dla stabilności systemu."
    strings:
        $w1 = "WinZip Computing" ascii nocase
        $w2 = "Registry Optimizer" ascii nocase
        $w3 = "wzro.exe" ascii nocase fullword
    condition:
        (uint16(0) == 0x5A4D) and (all of them)
}

rule VCEngine_PUP_Restoro_Reimage {
    meta:
        display_name = "VCEngine/PUP.Win32.Restoro"
        description = "Wykryto Restoro/Reimage Repair. Program typu Scareware, który straszy uszkodzeniem systemu Windows, aby wyłudzić opłatę za naprawę."
    strings:
        $r1 = "Restoro" ascii nocase
        $r2 = "Reimage Repair" ascii nocase
        $r3 = "reimageplus.com" ascii nocase
        $r4 = "restoro.com" ascii nocase
    condition:
        (uint16(0) == 0x5A4D) and (all of them)
}

rule VCEngine_PUP_SlimCleaner {
    meta:
        display_name = "VCEngine/PUP.Win32.SlimCleaner"
        description = "Wykryto SlimCleaner Plus. Program uciążliwy, który często spowalnia system i wyświetla natrętne powiadomienia o optymalizacji."
    strings:
        $s1 = "SlimCleaner" ascii nocase
        $s2 = "SlimWare Utilities" ascii nocase
        $s3 = "SlimCleanerPlus.exe" ascii nocase fullword
    condition:
        (uint16(0) == 0x5A4D) and (all of them)
}

rule VCEngine_PUP_Wondershare_Helper {
    meta:
        display_name = "VCEngine/PUP.Win32.WondershareHelper"
        description = "Wykryto Wondershare Helper Compact. Pozostałość po programach Wondershare, która działa w tle, zużywa RAM i jest trudna do usunięcia."
    strings:
        $w1 = "Wondershare Helper Compact" ascii nocase
        $w2 = "WSHelper.exe" ascii nocase fullword
        $w3 = "WsHelperService" ascii nocase fullword
    condition:
        (uint16(0) == 0x5A4D) and (all of them)
}

rule VCEngine_PUP_DriverBooster_Unofficial {
    meta:
        display_name = "VCEngine/PUP.Win32.DriverBooster"
        description = "Wykryto nieoficjalną lub zmodyfikowaną wersję Driver Booster. Może zawierać dodatkowe Adware lub niechciane paski narzędzi."
    strings:
        $d1 = "Driver Booster" ascii nocase
        $d2 = "IObit" ascii nocase fullword
        $d3 = "DriverBooster.exe" ascii nocase fullword
        $d4 = "Advanced SystemCare" ascii nocase
    condition:
        (uint16(0) == 0x5A4D) and (all of them)
}

rule VCEngine_Adware_OpenCandy {
    meta:
        display_name = "VCEngine/Adware.Win32.OpenCandy"
        description = "Wykryto OpenCandy. Moduł instalujący niechciane oprogramowanie bez zgody użytkownika."
    strings:
        $s1 = "OpenCandy" ascii nocase fullword
        $s2 = "ocsetupHlp.dll" ascii nocase fullword
        $s3 = "api.opencandy.com" ascii nocase
    condition:
        (uint16(0) == 0x5A4D) and (all of them)
}

rule VCEngine_PUP_ByteFence {
    meta:
        display_name = "VCEngine/PUP.Win32.ByteFence"
        description = "Wykryto ByteFence. Program zmieniający ustawienia wyszukiwania i instalowany bez wiedzy użytkownika."
    strings:
        $b1 = "ByteFence" ascii nocase fullword
        $b2 = "bytefence.com" ascii nocase
    condition:
        (uint16(0) == 0x5A4D) and (all of them)
}

rule VCEngine_PUP_Segurazo {
    meta:
        display_name = "VCEngine/PUP.Win32.Segurazo"
        description = "Wykryto Segurazo (SAntivirus). Agresywny program Scareware trudny do usunięcia."
    strings:
        $a1 = "Segurazo" ascii nocase fullword
        $a2 = "SAntivirus" ascii nocase fullword
        $a3 = "SegurazoUninstaller.exe" ascii nocase fullword
    condition:
        (uint16(0) == 0x5A4D) and (all of them)
}

rule VCEngine_PUP_IObit_Nagware {
    meta:
        display_name = "VCEngine/PUP.Win32.IObitSpammer"
        description = "Wykryto moduły IObit wyświetlające agresywne reklamy i powiadomienia."
    strings:
        $io1 = "IObit Uninstaller" ascii nocase
        $io2 = "LiveUpdate.exe" ascii nocase fullword
        $io3 = "Promote" ascii nocase fullword
    condition:
        (uint16(0) == 0x5A4D) and (all of them)
}

rule VCEngine_PUP_PC_SpeedUp {
    meta:
        display_name = "VCEngine/PUP.Win32.PCSpeedUp"
        description = "Wykryto fałszywy optymalizator systemu PC Speed Up."
    strings:
        $p1 = "PC Speed Up" ascii nocase
        $p2 = "pcspeedup.exe" ascii nocase fullword
    condition:
        (uint16(0) == 0x5A4D) and (all of them)
}

rule VCEngine_PUP_DriverPack_Manual {
    meta:
        display_name = "VCEngine/PUP.Win32.DriverPack"
        description = "Wykryto DriverPack Solution. Instaluje zbędne sterowniki i oprogramowanie trzecie."
    strings:
        $dr1 = "DriverPack" ascii nocase
        $dr2 = "drp.su" ascii nocase
    condition:
        (uint16(0) == 0x5A4D) and (all of them)
}

rule VCEngine_FakeAV_Legacy_2000 {
    meta:
        display_name = "VCEngine/FakeAV.Win32.LegacyGen"
        description = "Wykryto klasyczny fałszywy antywirus (FakeAV). Program imituje skanowanie i wyświetla nieprawdziwe komunikaty o infekcjach."
    strings:
        $a1 = "Antivirus 2000" ascii nocase fullword
        $a2 = "Antivirus 2009" ascii nocase fullword
        $a3 = "XP Antivirus" ascii nocase fullword
        $a4 = "Your computer is infected!" ascii nocase
        $a5 = "System Tool" ascii nocase fullword
    condition:
        (uint16(0) == 0x5A4D) and (3 of them)
}

rule VCEngine_FakeAV_SystemCare {
    meta:
        display_name = "VCEngine/FakeAV.Win32.SystemCare"
        description = "Wykryto System Care Antivirus. Agresywny FakeAV blokujący narzędzia systemowe i wymuszający płatność."
    strings:
        $s1 = "System Care Antivirus" ascii nocase
        $s2 = "scantime" ascii nocase fullword
        $s3 = "pay for full version" ascii nocase
    condition:
        (uint16(0) == 0x5A4D) and (all of them)
}

rule VCEngine_FakeAV_Win7_Protect {
    meta:
        display_name = "VCEngine/FakeAV.Win32.Win7Protect"
        description = "Wykryto podróbkę narzędzia Windows Security Center. Wykorzystuje interfejs systemowy do oszustwa."
    strings:
        $w1 = "Windows 7 Antivirus" ascii nocase
        $w2 = "Windows XP Antivirus" ascii nocase
        $w3 = "Windows Protection Suite" ascii nocase
        $w4 = "Security Tool" ascii nocase fullword
    condition:
        (uint16(0) == 0x5A4D) and (2 of them)
}

rule VCEngine_FakeAV_SmartFortress {
    meta:
        display_name = "VCEngine/FakeAV.Win32.SmartFortress"
        description = "Wykryto Smart Fortress 2012. Fałszywe oprogramowanie zabezpieczające blokujące uruchamianie aplikacji."
    strings:
        $sf1 = "Smart Fortress 2012" ascii nocase
        $sf2 = "SmartFortress" ascii nocase fullword
        $sf3 = "Infection found!" ascii nocase
    condition:
        (uint16(0) == 0x5A4D) and (all of them)
}

rule VCEngine_Spyware_Adups_FOTA
{
    meta:
        display_name = "VCEngine/Spyware.Android.Adups"
        description = "Wykrywa komponenty szpiegowskie firmy Adups zbierające dane prywatne"
    strings:
        $pkg = "com.adups.fota" ascii nocase
        $app = "AdupsFota" ascii nocase
        
        $act1 = "AdSafe_pro" ascii 
        $act2 = "com.adups.fota.sysoper.REBOOT" ascii
        $act3 = "checkcommand" ascii
    condition:
        any of them
}

rule VCEngine_Backdoor_XFota_Comprehensive
{
    meta:
        display_name = "VCEngine/Backdoor.Android.XFota.Network"
        description = "Wykrywa ślady aktywności XFota na podstawie domen i parametrów URL"
    strings:
        
        $d1 = "ota.xbkpota.com" ascii nocase
        $d2 = "notes.xbkptek.com" ascii nocase
        $d3 = "rsteptech.com" ascii nocase
        
       
        $u1 = "IMSI=" ascii
        $u2 = "UUID=OTA-" ascii
        $u3 = "QUDAOSHANG=9106" ascii 
        $u4 = "SOFT_VERSION=4s" ascii
        
        
        $p1 = "res/drawable-hdpi/xfota.png" ascii
        $p2 = "res/drawable-hdpi/xfota2.png" ascii
    condition:
        (any of ($d*)) or (3 of ($u*)) or (any of ($p*))
}

rule VCEngine_Locker_Android_HQ
{
    meta:
        display_name = "VCEngine/Locker.Android.HQ"
        description = "SARA Ransomware Detection"
    strings:
        $s1 = "Your phone has been locked" ascii nocase
        $s2 = "ransomware" ascii nocase
        $s3 = "com.sara.locker" ascii nocase
        $s4 = "unlock_code" ascii nocase
        $s5 = "Enter password to decrypt" ascii nocase
    condition:
        uint16(0) == 0x4B50 and (2 of ($s*))
}

rule VCEngine_Stealer_Chromium_Delta
{
    meta:
        display_name = "VCEngine/Stealer.Chromium.Delta"
        description = "Wykrywa szkodliwy komponent Delta Adblocker (Stealer)"
    strings:
        $s1 = "Delta Adblocker" ascii nocase
        $s2 = "delta_triangle_icon" ascii nocase
        $s3 = "red_black_shield" ascii nocase
        $s4 = "chrome.cookies.get" ascii
        $s5 = "chrome.identity.getProfileUserInfo" ascii
        $s6 = "upload_stolen_data" ascii nocase
        $s7 = "background_script_delta" ascii
    condition:
        (uint16(0) == 0x4B50 or uint16(0) == 0x5A4D) and (3 of ($s*))
}

rule VCEngine_Miner_WASM_Hidden
{
    meta:
        display_name = "VCEngine/Miner.WASM.Hidden"
description = "Kopie Bitcoin w przeglądarce bez wiedzy użytkownika."
    strings:
        $s1 = "WebAssembly.instantiate" ascii
        $s2 = "cryptonight" ascii nocase
        $s3 = "coinhive" ascii nocase
        $s4 = "throttleMiner" ascii
    condition:
        2 of them
}

rule VCEngine_Spyware_Keylogger_Artemis
{
    meta:
        display_name = "VCEngine/Spyware.Keylogger.Artemis"
    strings:
        $s1 = "GetAsyncKeyState" ascii
        $s2 = "SetWindowsHookEx" ascii
        $s3 = "logs.txt" ascii
        $s4 = "smtp_server" ascii
    condition:
        (uint16(0) == 0x5A4D) and all of them
}
