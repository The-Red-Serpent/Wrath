# Define Colors
$Red = "Red"
$Green = "Green"
$Yellow = "Yellow"
$Cyan = "Cyan"
$Blue = "Blue"

# Pretty Print Helper Function
function Print-Section($title) {
    Write-Host ""
    Write-Host ("-" * 80) -ForegroundColor $Blue
    Write-Host "[+] $title" -ForegroundColor $Green
    Write-Host ("-" * 80) -ForegroundColor $Blue
}

function User_Enumeration {
    Print-Section "User Enumeration"

    Write-Host "`n[*] Current User" -ForegroundColor $Cyan
    Write-Host "    $(whoami)" -ForegroundColor $Yellow

    Write-Host "`n[*] Current User Privileges (Check for SeImpersonate, etc.)" -ForegroundColor $Cyan
    whoami /priv | Out-String | Write-Host -ForegroundColor $Yellow

    Write-Host "`n[*] Local User Accounts" -ForegroundColor $Cyan
    Get-LocalUser | Format-Table Name, Enabled, LastLogon, Description -AutoSize

    Write-Host "`n[*] User Group Memberships" -ForegroundColor $Cyan
    whoami /groups | Out-String | Write-Host -ForegroundColor $Yellow
}

function System_Enumeration {
    Print-Section "System Enumeration"

    Write-Host "`n[*] OS Information" -ForegroundColor $Cyan
    systeminfo | Select-String "OS Name", "OS Version", "System Type" | Write-Host -ForegroundColor $Yellow

    Write-Host "`n[*] Disk Information" -ForegroundColor $Cyan
    Get-Volume | Format-Table DriveLetter, FileSystemLabel, FileSystem, SizeRemaining, Size -AutoSize

    Write-Host "`n[*] Installed Hotfixes" -ForegroundColor $Cyan
    Get-HotFix | Sort-Object InstalledOn | Format-Table Description, HotFixID, InstalledOn -AutoSize

    Write-Host "`n[*] UAC Settings" -ForegroundColor $Cyan
    reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableLUA | Out-String | Write-Host -ForegroundColor $Yellow
}

function Software_Enumeration {
    Print-Section "Software Enumeration"

    Write-Host "`n[*] Installed Software" -ForegroundColor $Cyan
    Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*" -ErrorAction SilentlyContinue |
        Select-Object DisplayName, DisplayVersion, Publisher | Format-Table -AutoSize
}

function Network_Enumeration {
    Print-Section "Network Enumeration"

    Write-Host "`n[*] IP Configuration" -ForegroundColor $Cyan
    ipconfig /all | Out-String | Write-Host -ForegroundColor $Yellow

    Write-Host "`n[*] Open Ports & Network Connections" -ForegroundColor $Cyan
    netstat -naob | Out-String | Write-Host -ForegroundColor $Yellow
}

function AV_Enumeration {
    Print-Section "Antivirus & Firewall Enumeration"

    Write-Host "`n[*] Installed Antivirus Software" -ForegroundColor $Cyan
    Get-WmiObject -Namespace "Root\SecurityCenter2" -Class AntiVirusProduct -ErrorAction SilentlyContinue |
        Select-Object displayName, productState | Format-Table -AutoSize

    Write-Host "`n[*] Active Firewall Rules" -ForegroundColor $Cyan
    Get-NetFirewallRule | Where-Object { $_.Enabled -eq $true } |
        Get-NetFirewallPortFilter | Format-Table DisplayName, LocalPort, Protocol -AutoSize
}

function Scheduled_Tasks_Enumeration {
    Print-Section "Scheduled Tasks Enumeration"

    Write-Host "`n[*] Scheduled Tasks Running as SYSTEM" -ForegroundColor $Cyan
    Get-ScheduledTask | Where-Object { $_.Principal.UserId -eq 'SYSTEM' } | Format-Table TaskName, State, TaskPath -AutoSize
}

function Services_Enumeration {
    Print-Section "Services Enumeration"

    Write-Host "`n[*] Auto-Start Services (Look for weak permissions)" -ForegroundColor $Cyan
    Get-Service | Where-Object { $_.StartType -eq 'Auto' } | Format-Table Name, DisplayName, Status, StartType -AutoSize
}

function Environment_Variables_Enumeration {
    Print-Section "Environment Variables Enumeration"

    Write-Host "`n[*] System Environment Variables" -ForegroundColor $Cyan
    Get-ChildItem -Path Env: | Format-Table Name, Value -AutoSize
}

function Insecure_GUI_Apps {
    Print-Section "Insecure GUI Applications"

    Write-Host "`n[*] Processes Running as Administrator (Potential UAC Bypass)" -ForegroundColor $Cyan
    Get-Process -IncludeUserName -ErrorAction SilentlyContinue |
        Where-Object { $_.UserName -like "*Administrator*" -or $_.UserName -eq (whoami) } |
        Format-Table Name, Id, UserName, Path -AutoSize
}

function AppLocker_Enumeration {
    Print-Section "AppLocker Policy Enumeration"

    Write-Host "`n[*] AppLocker Policy Rules" -ForegroundColor $Cyan
    Get-AppLockerPolicy -Effective -ErrorAction SilentlyContinue |
        Select-Object -ExpandProperty RuleCollections | Format-Table -AutoSize
}

# Menu to Choose an Option
function Show-Menu {
    Clear-Host
    Write-Host "===============================" -ForegroundColor $Blue
    Write-Host "  Windows Privilege Escalation" -ForegroundColor $Green
    Write-Host "===============================" -ForegroundColor $Blue
    Write-Host "1. User Enumeration"
    Write-Host "2. System Enumeration"
    Write-Host "3. Software Enumeration"
    Write-Host "4. Network Enumeration"
    Write-Host "5. Antivirus Enumeration"
    Write-Host "6. Insecure GUI Apps"
    Write-Host "7. AppLocker Enumeration"
    Write-Host "8. Scheduled Tasks Enumeration"
    Write-Host "9. Services Enumeration"
    Write-Host "10. Environment Variables Enumeration"
    Write-Host "11. Exit"
    Write-Host "===============================" -ForegroundColor $Blue

    $choice = Read-Host "Enter the number of the option you want to run"

    switch ($choice) {
        1 { User_Enumeration }
        2 { System_Enumeration }
        3 { Software_Enumeration }
        4 { Network_Enumeration }
        5 { AV_Enumeration }
        6 { Insecure_GUI_Apps }
        7 { AppLocker_Enumeration }
        8 { Scheduled_Tasks_Enumeration }
        9 { Services_Enumeration }
        10 { Environment_Variables_Enumeration }
        11 { Exit }
        default { Write-Host "Invalid choice, please try again!" -ForegroundColor $Red }
    }
}

Show-Menu
