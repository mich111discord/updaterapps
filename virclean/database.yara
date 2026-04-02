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
        $m1 = "McAfee, LLC" nocase wide ascii
        $m2 = "McAfee Security" nocase wide ascii
        $m3 = "McAfee Installer" nocase wide ascii
        $p1 = "McUICnt.exe" nocase wide ascii
        $p2 = "mclinst.exe" nocase wide ascii
    condition:
        uint16(0) == 0x5A4D and ($m1 or $m2 or $m3 or $p2)
}

rule VCEngine_PUP_Norton_Setup
{
    strings:
        $n1 = "Norton Download Manager" nocase wide ascii
        $n2 = "Symantec Corporation" nocase wide ascii
        $n3 = "NortonInstall" nocase wide ascii
        $p1 = "NSDownloader.exe" nocase wide ascii
    condition:
        uint16(0) == 0x5A4D and ($n1 or $n3 or $p1) and $n2
}
