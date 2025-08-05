@echo off
REM Fake malicious behavior for Wazuh FIM testing
echo Starting dummy operations...
mkdir "%TEMP%\WazuhTestFolder"
echo "Wazuh FIM test" > "%TEMP%\WazuhTestFolder\testfile.txt"
del "%TEMP%\WazuhTestFolder\testfile.txt"
rmdir "%TEMP%\WazuhTestFolder"
echo Completed test operations.
pause
