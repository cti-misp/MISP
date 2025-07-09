:: Simple script to run protect malicious.
:: The script executes a powershell script and appends output.
@ECHO OFF
ECHO.

powershell.exe -executionpolicy ByPass -File "C:\Program Files (x86)\ossec-agent\active-response\bin\block-malicious.ps1"

:Exit
