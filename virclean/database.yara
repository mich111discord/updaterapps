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
    meta:
        description = "Wykrywa Norton Power Eraser jako narzędzie wysokiego ryzyka (HarmTool)"
        author = "VirCleanEngine"
        severity = "Medium"

    strings:
        
        $s1 = "Norton Power Eraser" nocase wide ascii
        $s2 = "NPE.exe" nocase wide ascii
        $s3 = "Symantec Corporation" nocase wide ascii
        
        
        $f1 = "PowerEraser" nocase wide ascii
        $f2 = "Symantec Eraser" nocase wide ascii

    condition:
        
        uint16(0) == 0x5A4D and ($s1 or $f1) and $s3
}
