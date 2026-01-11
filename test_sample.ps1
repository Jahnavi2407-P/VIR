# PowerShell test script for file-type awareness
New-Item -Path "C:\test_directory" -ItemType Directory
Set-Content -Path "C:\test_file.txt" -Value "test content"
Rename-Item -Path "C:\test_file.txt" -NewName "C:\test_file.txt.locked"
