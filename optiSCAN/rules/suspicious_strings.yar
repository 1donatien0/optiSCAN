/*
    Règle qui détecte des chaînes suspectes
*/

rule SuspiciousPowerShell
{
    meta:
        description = "Detects suspicious PowerShell commands"
        severity = "medium"
        
    strings:
        $ps1 = "powershell -ExecutionPolicy Bypass" nocase
        $ps2 = "powershell -enc" nocase
        $ps3 = "Invoke-Expression" nocase
        $ps4 = "IEX" nocase
        
    condition:
        2 of them
}

rule SuspiciousDownloads
{
    meta:
        description = "Detects suspicious download patterns"
        severity = "low"
        
    strings:
        $wget = "wget" nocase
        $curl = "curl" nocase
        $download = "download" nocase
        
    condition:
        any of them
}