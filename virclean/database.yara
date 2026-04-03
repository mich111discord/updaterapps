rule VCEngine_Trojan_Bat_ForkBomb_Gen
{
    strings:
        $label = /:[a-zA-Z0-9_-]+/
        $start = /start\s+("%~nx0"|%0|%~f0)/ nocase
        $goto = /goto\s+:[a-zA-Z0-9_-]+/ nocase
    condition:
        filesize < 2KB and all of them
}

rule VCEngine_NPE_HarmTool_Enhanced
{
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
    strings:
        $m1 = "McAfee, LLC" nocase wide ascii
        $m2 = "mclinst.exe" nocase wide ascii
        $n1 = "Symantec Corporation" nocase wide ascii
        $n2 = "NSDownloader.exe" nocase wide ascii
        $n3 = "NortonDownloadManager" nocase wide ascii
    condition:
        uint16(0) == 0x5A4D and (2 of them)
}

rule VCEngine_Exploit_RCE_DarkSword_Strict
{
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
    strings:
        $s1 = "Net.WebClient" nocase
        $s2 = "DownloadFile" nocase
        $s3 = "Invoke-Expression" nocase
        $s4 = "IEX" nocase
        $s5 = "WScript.Shell" nocase
    condition:
        3 of them
}
