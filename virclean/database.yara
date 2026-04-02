rule VCEngine_Trojan_Bat_ForkBomb_Gen
{
    strings:
        $a = /start\s+/ nocase
        $b = /:[a-zA-Z0-9]+/
        $c = /goto\s+[a-zA-Z0-9]+/ nocase
    condition:
        all of them
}

rule VCEngine_NPE_HarmTool_Gen
{
    strings:
        $s1 = "Norton" nocase wide ascii
        $s2 = "Power Eraser" nocase wide ascii
    condition:
        $s1 or $s2
}

rule VCEngine_PUP_McAfee_Setup
{
    strings:
        $m1 = "McAfee" nocase wide ascii
        $m2 = "mclinst" nocase wide ascii
        $m3 = "McUICnt" nocase wide ascii
    condition:
        uint16(0) == 0x5A4D and any of them
}

rule VCEngine_PUP_Norton_Setup
{
    strings:
        $n1 = "Norton" nocase wide ascii
        $n2 = "Symantec" nocase wide ascii
        $n3 = "NSDownloader" nocase wide ascii
    condition:
        uint16(0) == 0x5A4D and any of them
}

rule VCEngine_Exploit_RCE_DarkSword_Gen
{
    strings:
        $s1 = "DarkSword" nocase wide ascii
        $s2 = "payload" nocase wide ascii
        $s3 = "reverse_shell" nocase wide ascii
        $s4 = "exploit" nocase wide ascii
        $s5 = "RCE" nocase wide ascii
        $s6 = "shellcode" nocase wide ascii
    condition:
        (uint16(0) == 0x5A4D or uint16(0) == 0x4B50) and (2 of them)
}
