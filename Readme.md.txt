PCTurboBoost
PowerShell Windows License
PCTurboBoost is a PowerShell script designed to optimize and turbocharge your Windows PC by improving performance, removing unnecessary applications, and repairing system issues. It provides a user-friendly interface with modular functions to enhance system health, making it ideal for both casual users and power users.
Features
System Diagnostics: Analyze CPU, disk, and RAM usage to assess system health.

Performance Optimization:
Adjust registry settings for better performance and privacy.

Disable unnecessary startup programs and animations.

Set the power plan to High Performance.

Stop non-essential background services.

Application Removal: Uninstall pre-configured or user-selected Windows Store apps.

Disk Cleanup: Remove temporary files and optimize the C: drive.

System Repair: Fix system files, Windows Update issues, and disk errors.

Portable Mode: Run without permanent changes to the system (default).

Logging: Generate detailed reports and audit logs for transparency.

Silent Mode: Automate tasks without user prompts for scripting.

Prerequisites
Operating System: Windows 10 or 11

PowerShell: Version 5.1 or later (pre-installed on Windows 10/11)

Administrative Privileges: Required for most operations

To check your PowerShell version:
powershell

$PSVersionTable.PSVersion

Installation
Download the Script:
Clone the repository or download the ZIP file from GitHub:
bash

git clone https://github.com/chaos2024/PCTurboBoost.git

Alternatively, download PCTurboBoost.ps1 and RunTurboBoost.bat directly from the Releases page.

Prepare the Files:
Place PCTurboBoost.ps1 and RunTurboBoost.bat in the same directory.

Execution Policy (Optional):
If your system’s PowerShell execution policy is Restricted, the script will prompt to set it to Bypass for the current user. Alternatively, run this manually:
powershell

Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy Bypass -Force

Usage
Recommended Method
Double-click RunTurboBoost.bat to launch the script with administrative privileges.

Follow the on-screen prompts to select options from the menu.

Command Line Options
Run PCTurboBoost.ps1 directly via PowerShell with optional parameters:
powershell

.\PCTurboBoost.ps1 [-Verbose] [-OutputPath "C:\Path"] [-ConfigFile "custom.json"] [-Portable] [-Silent]

-Verbose: Display detailed output.

-OutputPath: Specify where logs are saved (default: script directory).

-ConfigFile: Use a custom config file for app removal (default: config.json).

-Portable: Run in portable mode, saving logs to %TEMP%\PCTurboBoost (default: enabled).

-Silent: Automate without prompts (uses defaults).

Example:
powershell

.\PCTurboBoost.ps1 -Verbose -Silent

Menu Options
Check PC: View system info and health diagnostics.

Speed Up: Optimize performance settings and services.

Remove Apps: Uninstall specified Windows apps.

Configure Apps: Edit the app removal list.

Repair System: Fix system issues (files, updates, disk).

Exit: Close the script.

Type help in the menu for detailed instructions.
Configuration
The script uses a config.json file to manage the list of apps to remove. If it doesn’t exist, a default list is created (non-portable mode only). Edit it manually or use the "Configure Apps" menu option.
Default config.json:
json

{
  "AppsToRemove": [
    "Microsoft.SkypeApp", "Microsoft.Teams", "Microsoft.XboxApp", "Microsoft.MixedReality.Portal",
    "Microsoft.GetHelp", "Microsoft.People", "Microsoft.WindowsFeedbackHub", "Microsoft.YourPhone",
    "Microsoft.ZuneMusic", "Microsoft.ZuneVideo", "Microsoft.BingNews", "Microsoft.BingWeather",
    "Microsoft.MicrosoftSolitaireCollection", "Microsoft.3DBuilder", "Microsoft.WindowsMaps",
    "Microsoft.Getstarted", "Microsoft.Messaging", "Microsoft.WindowsCamera"
  ]
}

Output
Report File: TurboBoost_Report_YYYYMMDD_HHMMSS.txt (non-portable mode only)

Audit Log: TurboBoost_Audit_YYYYMMDD_HHMMSS.log (detailed actions)

Portable Mode: Logs are saved to %TEMP%\PCTurboBoost.

Safety Notes
Administrative Rights: Required for most changes (handled by RunTurboBoost.bat).

Backups: Registry changes are backed up before optimization (non-portable mode).

Reversible: Most changes can be undone manually (e.g., re-enable services, reinstall apps).

Restart: App removal may require a restart to finalize.

Contributing
Fork the repository.

Create a feature branch (git checkout -b feature-name).

Commit your changes (git commit -m "Add feature").

Push to the branch (git push origin feature-name).

Open a Pull Request.

Suggestions and bug reports are welcome via Issues.
License
This project is licensed under the MIT License - see the LICENSE file for details.
Acknowledgments
Built with PowerShell for Windows optimization.

Inspired by community tools for PC performance enhancement.

