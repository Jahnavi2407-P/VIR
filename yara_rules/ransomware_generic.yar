/*
    YARA Rules for Ransomware Detection
    Ransomware Behavior Analyzer Project
    
    These rules detect common ransomware families and behaviors.
    Use with caution - may produce false positives on legitimate software.
*/

// Generic Ransomware Indicators
rule ransomware_generic_strings
{
    meta:
        description = "Generic ransomware string indicators"
        author = "Ransomware Behavior Analyzer"
        severity = "high"
        category = "ransomware"
    
    strings:
        $ransom1 = "YOUR FILES HAVE BEEN ENCRYPTED" ascii wide nocase
        $ransom2 = "your files are encrypted" ascii wide nocase
        $ransom3 = "decrypt your files" ascii wide nocase
        $ransom4 = "restore your files" ascii wide nocase
        $ransom5 = "bitcoin" ascii wide nocase
        $ransom6 = "ransom" ascii wide nocase
        $ransom7 = "payment" ascii wide nocase
        $ransom8 = ".onion" ascii wide
        $ransom9 = "tor browser" ascii wide nocase
        $ransom10 = "wallet address" ascii wide nocase
        
    condition:
        3 of ($ransom*)
}

rule ransomware_crypto_apis
{
    meta:
        description = "Detects use of Windows Crypto APIs commonly used by ransomware"
        author = "Ransomware Behavior Analyzer"
        severity = "medium"
        category = "crypto"
    
    strings:
        $api1 = "CryptEncrypt" ascii wide
        $api2 = "CryptDecrypt" ascii wide
        $api3 = "CryptGenKey" ascii wide
        $api4 = "CryptAcquireContext" ascii wide
        $api5 = "CryptImportKey" ascii wide
        $api6 = "CryptExportKey" ascii wide
        $api7 = "BCryptEncrypt" ascii wide
        $api8 = "BCryptDecrypt" ascii wide
        $api9 = "CryptCreateHash" ascii wide
        $api10 = "CryptHashData" ascii wide
        
        // OpenSSL
        $ssl1 = "EVP_EncryptInit" ascii wide
        $ssl2 = "EVP_CipherUpdate" ascii wide
        $ssl3 = "RSA_public_encrypt" ascii wide
        $ssl4 = "AES_encrypt" ascii wide
        
    condition:
        (uint16(0) == 0x5A4D) and (4 of ($api*) or 2 of ($ssl*))
}

rule ransomware_file_extensions
{
    meta:
        description = "Detects ransomware encrypted file extensions"
        author = "Ransomware Behavior Analyzer"
        severity = "high"
        category = "ransomware"
    
    strings:
        $ext1 = ".locked" ascii wide
        $ext2 = ".encrypted" ascii wide
        $ext3 = ".crypt" ascii wide
        $ext4 = ".enc" ascii wide
        $ext5 = ".crypted" ascii wide
        $ext6 = ".lockbit" ascii wide
        $ext7 = ".revil" ascii wide
        $ext8 = ".conti" ascii wide
        $ext9 = ".ryuk" ascii wide
        $ext10 = ".WNCRY" ascii wide
        $ext11 = ".locky" ascii wide
        $ext12 = ".cerber" ascii wide
        $ext13 = ".dharma" ascii wide
        $ext14 = ".phobos" ascii wide
        $ext15 = ".maze" ascii wide
        
    condition:
        2 of ($ext*)
}

rule ransomware_shadow_delete
{
    meta:
        description = "Detects shadow copy deletion commands"
        author = "Ransomware Behavior Analyzer"
        severity = "critical"
        category = "evasion"
    
    strings:
        $vss1 = "vssadmin delete shadows" ascii wide nocase
        $vss2 = "vssadmin.exe delete shadows" ascii wide nocase
        $wmic1 = "wmic shadowcopy delete" ascii wide nocase
        $wmic2 = "WMIC.exe shadowcopy delete" ascii wide nocase
        $bcd1 = "bcdedit /set" ascii wide nocase
        $bcd2 = "recoveryenabled no" ascii wide nocase
        $wbadmin = "wbadmin delete" ascii wide nocase
        
    condition:
        any of them
}

rule ransomware_persistence
{
    meta:
        description = "Detects ransomware persistence mechanisms"
        author = "Ransomware Behavior Analyzer"
        severity = "high"
        category = "persistence"
    
    strings:
        $reg1 = "CurrentVersion\\Run" ascii wide
        $reg2 = "CurrentVersion\\RunOnce" ascii wide
        $reg3 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii wide
        $startup = "\\Startup\\" ascii wide
        $schtasks = "schtasks /create" ascii wide nocase
        
    condition:
        (uint16(0) == 0x5A4D) and (2 of them)
}
