/*
    YARA Rules for Specific Ransomware Families
    Ransomware Behavior Analyzer Project
*/

// LockBit Ransomware
rule ransomware_lockbit
{
    meta:
        description = "Detects LockBit ransomware family"
        author = "Ransomware Behavior Analyzer"
        severity = "critical"
        family = "LockBit"
        reference = "https://attack.mitre.org/software/S0372/"
    
    strings:
        $s1 = "LockBit" ascii wide nocase
        $s2 = ".lockbit" ascii wide
        $s3 = "Restore-My-Files.txt" ascii wide
        $s4 = "lockbit@" ascii wide nocase
        $s5 = "YOUR DATA IS STOLEN AND ENCRYPTED" ascii wide nocase
        
        // Mutex
        $mutex1 = "Global\\{GUID}" ascii wide
        
        // Code patterns
        $code1 = { 48 8B ?? ?? ?? ?? ?? 48 85 C0 74 ?? 48 8B ?? 48 83 ?? ?? 48 8B }
        
    condition:
        (uint16(0) == 0x5A4D) and (2 of ($s*) or $code1)
}

// REvil/Sodinokibi Ransomware
rule ransomware_revil
{
    meta:
        description = "Detects REvil/Sodinokibi ransomware family"
        author = "Ransomware Behavior Analyzer"
        severity = "critical"
        family = "REvil"
        alias = "Sodinokibi"
    
    strings:
        $s1 = "REvil" ascii wide nocase
        $s2 = "Sodinokibi" ascii wide nocase
        $s3 = "-readme.txt" ascii wide
        $s4 = "ATTENTION!" ascii wide
        $s5 = "decryptor.top" ascii wide nocase
        $s6 = "aplebzu47wgazapdqks6vrcv6zcnjppkbxbr6wketf56nf6aq2nmyoyd" ascii wide
        
        // Config pattern
        $cfg = "{\"pk\":" ascii
        
        // Extension pattern
        $ext = /\.[a-z0-9]{5,8}$/ ascii
        
    condition:
        (uint16(0) == 0x5A4D) and (2 of ($s*) or $cfg)
}

// Conti Ransomware
rule ransomware_conti
{
    meta:
        description = "Detects Conti ransomware family"
        author = "Ransomware Behavior Analyzer"
        severity = "critical"
        family = "Conti"
    
    strings:
        $s1 = "CONTI" ascii wide
        $s2 = ".CONTI" ascii wide
        $s3 = "readme.txt" ascii wide
        $s4 = "All of your files are currently encrypted" ascii wide nocase
        $s5 = "contirecovery" ascii wide nocase
        
        // Conti specific patterns
        $p1 = "mutex" ascii wide
        $p2 = "locker" ascii wide
        
    condition:
        (uint16(0) == 0x5A4D) and (2 of ($s*))
}

// Ryuk Ransomware
rule ransomware_ryuk
{
    meta:
        description = "Detects Ryuk ransomware family"
        author = "Ransomware Behavior Analyzer"
        severity = "critical"
        family = "Ryuk"
    
    strings:
        $s1 = "RYUK" ascii wide
        $s2 = ".RYK" ascii wide
        $s3 = "RyukReadMe" ascii wide
        $s4 = "UNIQUE_ID_DO_NOT_REMOVE" ascii wide
        $s5 = "No system is safe" ascii wide nocase
        
        // Known Ryuk PDB paths
        $pdb = "\\Ryuk\\" ascii wide nocase
        
    condition:
        (uint16(0) == 0x5A4D) and (2 of ($s*) or $pdb)
}

// WannaCry Ransomware
rule ransomware_wannacry
{
    meta:
        description = "Detects WannaCry ransomware family"
        author = "Ransomware Behavior Analyzer"
        severity = "critical"
        family = "WannaCry"
    
    strings:
        $s1 = "WannaCry" ascii wide nocase
        $s2 = "WNCRY" ascii wide
        $s3 = ".WNCRY" ascii wide
        $s4 = "@WanaDecryptor@" ascii wide
        $s5 = "WanaCrypt0r" ascii wide
        $s6 = "Ooops, your files have been encrypted!" ascii wide
        
        // Kill switch domain
        $kill = "iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com" ascii wide
        
        // MS17-010 exploitation
        $smb = "SMBv1" ascii wide
        
    condition:
        (uint16(0) == 0x5A4D) and (2 of ($s*) or $kill)
}

// DarkSide Ransomware
rule ransomware_darkside
{
    meta:
        description = "Detects DarkSide ransomware family"
        author = "Ransomware Behavior Analyzer"
        severity = "critical"
        family = "DarkSide"
    
    strings:
        $s1 = "DarkSide" ascii wide nocase
        $s2 = ".darkside" ascii wide
        $s3 = "README" ascii wide
        $s4 = "darksidc" ascii wide nocase
        $s5 = "Welcome to DarkSide" ascii wide
        
    condition:
        (uint16(0) == 0x5A4D) and (2 of ($s*))
}

// BlackCat/ALPHV Ransomware
rule ransomware_blackcat
{
    meta:
        description = "Detects BlackCat/ALPHV ransomware family"
        author = "Ransomware Behavior Analyzer"
        severity = "critical"
        family = "BlackCat"
        alias = "ALPHV"
    
    strings:
        $s1 = "BlackCat" ascii wide nocase
        $s2 = "ALPHV" ascii wide
        $s3 = ".alphv" ascii wide
        $s4 = "RECOVER-" ascii wide
        
        // Rust artifacts (BlackCat is written in Rust)
        $rust1 = ".rdata" ascii
        $rust2 = "rust_panic" ascii
        
    condition:
        (uint16(0) == 0x5A4D) and (2 of ($s*) or all of ($rust*))
}

// Maze Ransomware
rule ransomware_maze
{
    meta:
        description = "Detects Maze ransomware family"
        author = "Ransomware Behavior Analyzer"
        severity = "critical"
        family = "Maze"
    
    strings:
        $s1 = "MAZE" ascii wide
        $s2 = ".maze" ascii wide
        $s3 = "DECRYPT-FILES" ascii wide
        $s4 = "maze-news" ascii wide nocase
        $s5 = "Attention!" ascii wide
        
    condition:
        (uint16(0) == 0x5A4D) and (2 of ($s*))
}

// Phobos Ransomware
rule ransomware_phobos
{
    meta:
        description = "Detects Phobos ransomware family"
        author = "Ransomware Behavior Analyzer"
        severity = "critical"
        family = "Phobos"
    
    strings:
        $s1 = "Phobos" ascii wide nocase
        $s2 = ".phobos" ascii wide
        $s3 = ".id[" ascii wide
        $s4 = "info.txt" ascii wide
        $s5 = "info.hta" ascii wide
        
        // Extension pattern: .id[ID].[email].phobos
        $ext = /\.id\[[A-F0-9]{8}\]\.[^\]]+\.phobos/ ascii
        
    condition:
        (uint16(0) == 0x5A4D) and (2 of ($s*) or $ext)
}

// Dharma/Crysis Ransomware
rule ransomware_dharma
{
    meta:
        description = "Detects Dharma/Crysis ransomware family"
        author = "Ransomware Behavior Analyzer"
        severity = "critical"
        family = "Dharma"
        alias = "Crysis"
    
    strings:
        $s1 = "dharma" ascii wide nocase
        $s2 = "crysis" ascii wide nocase
        $s3 = ".dharma" ascii wide
        $s4 = ".wallet" ascii wide
        $s5 = "FILES ENCRYPTED" ascii wide nocase
        $s6 = "info.hta" ascii wide
        
        // ID pattern
        $id = /\.id-[A-F0-9]{8}\./ ascii
        
    condition:
        (uint16(0) == 0x5A4D) and (2 of ($s*) or $id)
}
