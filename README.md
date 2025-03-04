# Wrath - Windows Privilege Escalation Enumeration Script

## 🚀 Overview
Wrath is an Windows Privilege Escalation enumeration script designed to help security researchers and penetration testers identify potential privilege escalation vectors on Windows systems. The script automates various enumeration tasks, including user, system, software, network, antivirus, and security policy enumeration.

## 🎯 Features
- **User Enumeration**: Gathers information about user privileges, groups, and active accounts.
- **System Enumeration**: Collects OS details, hotfixes, disk information, and UAC settings.
- **Software Enumeration**: Lists installed applications, running processes, and unquoted service paths.
- **Network Enumeration**: Displays IP configuration, ARP table, routing table, and active network connections.
- **Antivirus Enumeration**: Identifies installed security software and firewall rules.
- **Insecure GUI Apps**: Detects applications running with elevated privileges.
- **AppLocker Enumeration**: Checks for restrictive execution policies and identifies writable directories.
- **Additional Enumeration** (To be added): Scheduled tasks, service misconfigurations, registry weaknesses, and more.

## 🛠️ Installation
```powershell
# Clone the repository
git clone https://github.com/YourUsername/Wrath.git
cd Wrath

# Run the script (PowerShell must be in unrestricted mode)
powershell -ExecutionPolicy Bypass -File .\Wrath.ps1
```

## 📌 Usage
1. Run `Wrath.ps1` as an administrator for comprehensive results.
2. Select an enumeration option from the interactive menu.
3. Analyze the output to identify possible privilege escalation paths.

## 📷 Example Output
```
-----------------------[+] User Enumeration ----------------------
Current User: RED-SERPENT\Administrator

Current Privileges:
SeImpersonatePrivilege          Enabled
SeAssignPrimaryTokenPrivilege   Enabled

All Local Users:
-------------------------------------------
 Name          Enabled  LastLogon        Description
--------------------------------------------------
 Admin        True     02-03-2025       Administrator Account
 Guest        False    N/A              Built-in Guest Account

Current User Groups:
--------------------------------------------------
Administrators, Remote Desktop Users, Backup Operators
```

## ⚠️ Disclaimer
Wrath is intended for ethical hacking and security research **only**. Unauthorized use on systems without permission is **strictly prohibited**. The developer is not responsible for any misuse of this tool.

## 🤝 Contributing
We welcome contributions! Feel free to fork the repository and submit pull requests with improvements or additional features.

## 📜 License
This project is licensed under the MIT License - see the `LICENSE` file for details.

---
### 🚀 Elevate Your Privilege Escalation Game with Wrath!

