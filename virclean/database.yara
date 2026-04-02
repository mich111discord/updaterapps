rule Trojan_Bat_ForkBomb_Gen
{
    strings:
        $a = /start\s+/ nocase
        $b = /:[a-zA-Z0-9]+/
        $c = /goto\s+[a-zA-Z0-9]+/ nocase
    condition:
        all of them
}
