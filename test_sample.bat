@echo off
REM Simple batch file for testing file-type awareness
mkdir C:\test_dir
echo test > C:\test_file.txt
ren C:\test_file.txt C:\test_file.txt.locked
