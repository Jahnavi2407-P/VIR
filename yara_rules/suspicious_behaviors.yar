/*
    YARA Rules for Suspicious Behaviors and Techniques
    Ransomware Behavior Analyzer Project
*/

// Anti-Analysis Detection
rule suspicious_anti_debug
{
    meta:
        description = "Detects anti-debugging techniques"
        author = "Ransomware Behavior Analyzer"
        severity = "medium"
        category = "evasion"
    
    strings:
        $api1 = "IsDebuggerPresent" ascii wide
        $api2 = "CheckRemoteDebuggerPresent" ascii wide
        $api3 = "NtQueryInformationProcess" ascii wide
        $api4 = "OutputDebugString" ascii wide
        $api5 = "GetTickCount" ascii wide
        $api6 = "QueryPerformanceCounter" ascii wide
        $api7 = "NtSetInformationThread" ascii wide
        
        // VM detection
        $vm1 = "VMware" ascii wide nocase
        $vm2 = "VirtualBox" ascii wide nocase
        $vm3 = "VBOX" ascii wide
        $vm4 = "QEMU" ascii wide
        $vm5 = "Sandboxie" ascii wide nocase
        
    condition:
        (uint16(0) == 0x5A4D) and (3 of ($api*) or 2 of ($vm*))
}

// Process Injection Techniques
rule suspicious_process_injection
{
    meta:
        description = "Detects process injection techniques"
        author = "Ransomware Behavior Analyzer"
        severity = "high"
        category = "injection"
    
    strings:
        $api1 = "VirtualAllocEx" ascii wide
        $api2 = "WriteProcessMemory" ascii wide
        $api3 = "CreateRemoteThread" ascii wide
        $api4 = "NtCreateThreadEx" ascii wide
        $api5 = "QueueUserAPC" ascii wide
        $api6 = "SetThreadContext" ascii wide
        $api7 = "NtUnmapViewOfSection" ascii wide
        $api8 = "RtlCreateUserThread" ascii wide
        
        // Process hollowing
        $hollow1 = "ZwUnmapViewOfSection" ascii wide
        $hollow2 = "NtResumeThread" ascii wide
        
    condition:
        (uint16(0) == 0x5A4D) and (3 of ($api*) or all of ($hollow*))
}

// Privilege Escalation
rule suspicious_privilege_escalation
{
    meta:
        description = "Detects privilege escalation attempts"
        author = "Ransomware Behavior Analyzer"
        severity = "high"
        category = "privilege"
    
    strings:
        $api1 = "AdjustTokenPrivileges" ascii wide
        $api2 = "OpenProcessToken" ascii wide
        $api3 = "LookupPrivilegeValue" ascii wide
        $api4 = "SeDebugPrivilege" ascii wide
        $api5 = "SeTakeOwnershipPrivilege" ascii wide
        $api6 = "SeBackupPrivilege" ascii wide
        
        // UAC bypass
        $uac1 = "fodhelper" ascii wide nocase
        $uac2 = "eventvwr" ascii wide nocase
        $uac3 = "CompMgmtLauncher" ascii wide nocase
        
    condition:
        (uint16(0) == 0x5A4D) and (3 of ($api*) or any of ($uac*))
}

// Network Communication
rule suspicious_network_activity
{
    meta:
        description = "Detects suspicious network activity patterns"
        author = "Ransomware Behavior Analyzer"
        severity = "medium"
        category = "network"
    
    strings:
        // Socket APIs
        $net1 = "WSAStartup" ascii wide
        $net2 = "socket" ascii wide
        $net3 = "connect" ascii wide
        $net4 = "send" ascii wide
        $net5 = "recv" ascii wide
        
        // HTTP APIs
        $http1 = "InternetOpen" ascii wide
        $http2 = "InternetConnect" ascii wide
        $http3 = "HttpOpenRequest" ascii wide
        $http4 = "HttpSendRequest" ascii wide
        $http5 = "WinHttpOpen" ascii wide
        
        // User agent strings
        $ua1 = "Mozilla/5.0" ascii wide
        $ua2 = "User-Agent:" ascii wide
        
    condition:
        (uint16(0) == 0x5A4D) and (3 of ($net*) or 3 of ($http*))
}

// File System Operations
rule suspicious_mass_file_operations
{
    meta:
        description = "Detects patterns of mass file operations"
        author = "Ransomware Behavior Analyzer"
        severity = "medium"
        category = "file"
    
    strings:
        // File enumeration
        $find1 = "FindFirstFile" ascii wide
        $find2 = "FindNextFile" ascii wide
        
        // File operations
        $file1 = "CreateFileW" ascii wide
        $file2 = "WriteFile" ascii wide
        $file3 = "ReadFile" ascii wide
        $file4 = "DeleteFileW" ascii wide
        $file5 = "MoveFileW" ascii wide
        
        // Path operations
        $path1 = "GetLogicalDrives" ascii wide
        $path2 = "GetDriveType" ascii wide
        
    condition:
        (uint16(0) == 0x5A4D) and (all of ($find*) and 3 of ($file*) and any of ($path*))
}

// Service Manipulation
rule suspicious_service_manipulation
{
    meta:
        description = "Detects service manipulation"
        author = "Ransomware Behavior Analyzer"
        severity = "high"
        category = "service"
    
    strings:
        $svc1 = "OpenSCManager" ascii wide
        $svc2 = "CreateService" ascii wide
        $svc3 = "StartService" ascii wide
        $svc4 = "ControlService" ascii wide
        $svc5 = "DeleteService" ascii wide
        
        // Service names commonly targeted
        $target1 = "vss" ascii wide nocase
        $target2 = "sql" ascii wide nocase
        $target3 = "backup" ascii wide nocase
        $target4 = "exchange" ascii wide nocase
        
    condition:
        (uint16(0) == 0x5A4D) and (3 of ($svc*) and any of ($target*))
}

// PowerShell Execution
rule suspicious_powershell
{
    meta:
        description = "Detects suspicious PowerShell patterns"
        author = "Ransomware Behavior Analyzer"
        severity = "high"
        category = "execution"
    
    strings:
        $ps1 = "powershell" ascii wide nocase
        $ps2 = "-ExecutionPolicy Bypass" ascii wide nocase
        $ps3 = "-enc " ascii wide nocase
        $ps4 = "-encodedcommand" ascii wide nocase
        $ps5 = "Invoke-Expression" ascii wide nocase
        $ps6 = "IEX" ascii wide
        $ps7 = "DownloadString" ascii wide
        $ps8 = "DownloadFile" ascii wide
        $ps9 = "-WindowStyle Hidden" ascii wide nocase
        $ps10 = "-NoProfile" ascii wide nocase
        
    condition:
        3 of ($ps*)
}

// Base64 Encoded Content
rule suspicious_base64_content
{
    meta:
        description = "Detects suspicious base64 encoded content"
        author = "Ransomware Behavior Analyzer"
        severity = "low"
        category = "obfuscation"
    
    strings:
        // Base64 encoded PowerShell commands
        $b64_ps1 = "JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYw" ascii // $client = New-Objec
        $b64_ps2 = "SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQALg" ascii // IEX(New-Object Net.
        
        // Large base64 strings
        $b64 = /[A-Za-z0-9+\/]{100,}={0,2}/
        
    condition:
        any of ($b64_ps*) or (#b64 > 5)
}

// Packed/Encrypted Executables
rule suspicious_packer
{
    meta:
        description = "Detects packed or encrypted executables"
        author = "Ransomware Behavior Analyzer"
        severity = "medium"
        category = "packer"
    
    strings:
        // UPX
        $upx1 = "UPX0" ascii
        $upx2 = "UPX1" ascii
        $upx3 = "UPX!" ascii
        
        // Other packers
        $aspack = ".aspack" ascii
        $petite = ".petite" ascii
        $nspack = ".nsp" ascii
        $mpress = ".MPRESS" ascii
        
    condition:
        (uint16(0) == 0x5A4D) and any of them
}
