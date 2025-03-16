# Version: 1.0.0

<#
    Startup Guide:
    - Save as "PCTurboBoost.ps1"
    - Create "RunTurboBoost.bat" in the same folder:
       @echo off
title Launching PCTurboBoost

:: Check if running as admin, and if not, request elevation
net session >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo Requesting administrative privileges...
    powershell -Command "Start-Process cmd -ArgumentList '/c %~f0' -Verb RunAs"
    exit /b
)

:: Run the PowerShell script with Bypass policy
echo Starting PCTurboBoost.ps1...
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0PCTurboBoost.ps1"
if %ERRORLEVEL% NEQ 0 (
    echo Error: Failed to run PCTurboBoost.ps1. Check the script or permissions.
    pause
    exit /b %ERRORLEVEL%
)

echo PCTurboBoost completed.
pause
    - Double-click "RunTurboBoost.bat" to launch (recommended method)
#>

param (
    [switch]$Verbose,
    [ValidateScript({ if (Test-Path -PathType Container -Path (Split-Path $_ -Parent)) { $true } else { throw "Invalid OutputPath parent directory" } })]
    [string]$OutputPath = $PSScriptRoot,
    [ValidateScript({ if ($_ -match '^[a-zA-Z0-9_\-\.]+$') { $true } else { throw "ConfigFile must be a simple filename (letters, numbers, underscore, hyphen, dot)" } })]
    [string]$ConfigFile = "config.json",
    [switch]$Portable = $true,  # Changed to default $true
    [switch]$Silent
)

# Utility Functions
function Confirm-Action {
    param ([string]$Message)
    if ($Silent) { return $true }
    Write-Host "$Message [Y/n] " -ForegroundColor Magenta -NoNewline
    $response = Read-Host
    return ($response -eq "" -or $response -match "^[Yy]$")
}

function Write-Report {
    param (
        [string]$Text,
        [string]$Type = "Success"
    )
    $color = switch ($Type) {
        "Success" { "Green" }
        "Warning" { "Yellow" }
        "Error" { "Red" }
    }
    Write-Host "$Text" -ForegroundColor $color
    try {
        $script:reportBuffer.Add("[$Type] $(Get-Date -Format 'HH:mm:ss') - $Text") | Out-Null
    } catch {
        Write-Host "Warning: Failed to log report - $($_.Exception.Message)" -ForegroundColor Yellow
    }
    if ($Verbose) { Write-Verbose "Details: $Text" }
}

function Write-Audit {
    param ([string]$Text)
    try {
        $script:auditBuffer.Add("[AUDIT] $(Get-Date -Format 'HH:mm:ss') - $Text") | Out-Null
    } catch {
        Write-Host "Warning: Failed to log audit - $($_.Exception.Message)" -ForegroundColor Yellow
    }
}

function Flush-Buffers {
    if (-not $Portable -and $script:reportBuffer.Count -gt 0) {
        try {
            $script:reportBuffer | Out-File -FilePath $outputFile -Append -ErrorAction Stop
        } catch {
            Write-Host "Error: Failed to write report to $outputFile - $($_.Exception.Message)" -ForegroundColor Red
        }
    }
    if ($script:auditBuffer.Count -gt 0) {
        try {
            $script:auditBuffer | Out-File -FilePath $auditLog -Append -ErrorAction Stop
        } catch {
            Write-Host "Error: Failed to write audit log to $auditLog - $($_.Exception.Message)" -ForegroundColor Red
        }
    }
    $script:reportBuffer.Clear()
    $script:auditBuffer.Clear()
}

function Test-Admin {
    $principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    $isAdmin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) {
        Write-Report "Error: Requires administrative rights. Run 'RunTurboBoost.bat' as administrator." "Error"
        exit 1
    }
    return $isAdmin
}

# Progress Bar
function Show-Progress {
    param (
        [int]$CurrentStep,
        [int]$TotalSteps,
        [string]$Activity
    )
    $percent = [math]::Round(($CurrentStep / $TotalSteps) * 100)
    Write-Host "$Activity - Step $CurrentStep of $TotalSteps ($percent% complete)" -ForegroundColor Cyan
}

# Main Script Logic
$script:Version = "1.0.0"
$asciiArt = @"

        |
       / \
      / _ \
     |.o '.|
     |'._.'|
     |     |
   ,'|  |  |`.
  /  |  |  |  \
  |,-'--|--'-.| l42
 ________  _____  ___  ____  ___  ____  ____  __________
/_  __/ / / / _ \/ _ )/ __ \/ _ )/ __ \/ __ \/ __/_  __/
 / / / /_/ / , _/ _  / /_/ / _  / /_/ / /_/ /\ \  / /   
/_/  \____/_/|_/____/\____/____/\____/\____/___/ /_/    
                                                        
"@
Write-Host $asciiArt -ForegroundColor Cyan
Write-Host "Welcome to PCTurboBoost v$script:Version - Turbocharge Your PC!" -ForegroundColor Green
Write-Host "Press Enter to begin..." -ForegroundColor Magenta
if (-not $Silent) { Read-Host }

# Cached data to avoid repeated queries
$script:cachedData = @{}

# Version and Execution Policy Check with Auto-Fix
if ($PSVersionTable.PSVersion.Major -lt 5) {
    Write-Host "Error: Requires PowerShell 5.1 or later. Current version: $($PSVersionTable.PSVersion)" -ForegroundColor Red
    exit 1
}
$execPolicy = Get-ExecutionPolicy
if ($execPolicy -eq "Restricted" -or $execPolicy -eq "AllSigned") {
    Write-Host "Warning: Execution policy ($execPolicy) may block this script." -ForegroundColor Yellow
    if (-not $Silent -and (Confirm-Action "Auto-fix policy to Bypass for current user? (Requires admin)")) {
        try {
            Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy Bypass -Force -ErrorAction Stop
            Write-Host "Policy set to Bypass. Please relaunch the script." -ForegroundColor Green
            exit 0
        } catch {
            Write-Host "Error: Failed to set policy - $($_.Exception.Message)" -ForegroundColor Red
            Write-Host "Run 'RunTurboBoost.bat' or manually set policy with: Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy Bypass" -ForegroundColor Yellow
            exit 1
        }
    } else {
        Write-Host "Use 'RunTurboBoost.bat' or run: Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy Bypass" -ForegroundColor Yellow
        exit 1
    }
}

# Normalize and validate OutputPath
$OutputPath = [System.IO.Path]::GetFullPath($OutputPath.Trim())
if ($Portable) {
    $OutputPath = "$env:TEMP\PCTurboBoost"
    if (-not (Test-Path $OutputPath)) {
        try {
            New-Item -Path $OutputPath -ItemType Directory -Force -ErrorAction Stop | Out-Null
            Write-Host "Portable mode enabled: Saving to $OutputPath" -ForegroundColor Yellow
        } catch {
            Write-Host "Error: Failed to create $OutputPath - $($_.Exception.Message)" -ForegroundColor Red
            exit 1
        }
    }
} elseif (-not (Test-Path $OutputPath)) {
    try {
        New-Item -Path $OutputPath -ItemType Directory -Force -ErrorAction Stop | Out-Null
    } catch {
        Write-Host "Error: Failed to create $OutputPath - $($_.Exception.Message)" -ForegroundColor Red
        exit 1
    }
}

$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$outputFile = Join-Path $OutputPath "TurboBoost_Report_$timestamp.txt"
$auditLog = Join-Path $OutputPath "TurboBoost_Audit_$timestamp.log"

$script:progress = [PSCustomObject]@{
    StepsCompleted = 0
    AppsRemoved = 0
}

$script:reportBuffer = [System.Collections.ArrayList]::new()
$script:auditBuffer = [System.Collections.ArrayList]::new()

# Config Setup
if (Test-Path $ConfigFile) {
    try {
        $config = Get-Content $ConfigFile -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
        if (-not $config.AppsToRemove) { $config.AppsToRemove = @("Microsoft.Teams", "Microsoft.BingNews") }
    } catch {
        Write-Host "Error: Failed to load config file '$ConfigFile' - $($_.Exception.Message)" -ForegroundColor Red
        exit 1
    }
} else {
    $config = [PSCustomObject]@{
        AppsToRemove = @(
            "Microsoft.SkypeApp", "Microsoft.Teams", "Microsoft.XboxApp", "Microsoft.MixedReality.Portal",
            "Microsoft.GetHelp", "Microsoft.People", "Microsoft.WindowsFeedbackHub", "Microsoft.YourPhone",
            "Microsoft.ZuneMusic", "Microsoft.ZuneVideo", "Microsoft.BingNews", "Microsoft.BingWeather",
            "Microsoft.MicrosoftSolitaireCollection", "Microsoft.3DBuilder", "Microsoft.WindowsMaps",
            "Microsoft.Getstarted", "Microsoft.Messaging", "Microsoft.WindowsCamera"
        )
    }
    if (-not $Portable) {
        try {
            $config | ConvertTo-Json | Set-Content $ConfigFile -ErrorAction Stop
        } catch {
            Write-Host "Warning: Failed to create config file '$ConfigFile' - $($_.Exception.Message)" -ForegroundColor Yellow
        }
    }
}

Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;

public class PerfCounter {
    [DllImport("kernel32.dll")]
    public static extern bool GetSystemTimes(out long idle, out long kernel, out long user);

    public static double GetCpuUsage(int sleepMs) {
        long idle1, kernel1, user1, idle2, kernel2, user2;
        GetSystemTimes(out idle1, out kernel1, out user1);
        System.Threading.Thread.Sleep(sleepMs);
        GetSystemTimes(out idle2, out kernel2, out user2);
        long sysTotal1 = kernel1 + user1;
        long sysTotal2 = kernel2 + user2;
        long idleDiff = idle2 - idle1;
        long sysDiff = sysTotal2 - sysTotal1;
        return sysDiff > 0 ? (1.0 - ((double)idleDiff / sysDiff)) * 100 : 0;
    }
}
"@

if (-not (Test-Admin)) { exit 1 }

# Cache initial system info
try {
    $script:cachedData["osInfo"] = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
    $script:cachedData["cpuInfo"] = Get-CimInstance Win32_Processor -ErrorAction Stop
} catch {
    Write-Host "Error: Failed to cache system info - $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

# Modularized Functions

function Get-SystemInfo {
    Write-Report "Collecting system information..." "Success"
    Show-Progress -CurrentStep 1 -TotalSteps 4 -Activity "Collecting system information"
    Write-Report "Operating System: $($script:cachedData["osInfo"].Caption)" "Success"
    Write-Report "Processor: $($script:cachedData["cpuInfo"].Name)" "Success"
    $script:progress.StepsCompleted++
}

function Run-Diagnostics {
    Write-Report "Analyzing system health..." "Success"
    Show-Progress -CurrentStep 2 -TotalSteps 4 -Activity "Analyzing system health"
    $health = [PSCustomObject]@{ CPU = 0; Disk = 100; RAM = 0 }
    
    try {
    $cpu = Get-CimInstance Win32_PerfFormattedData_PerfOS_Processor -ErrorAction Stop | 
           Where-Object { $_.Name -eq "_Total" } | 
           Select-Object -ExpandProperty PercentProcessorTime
    $health.CPU = [math]::Round(100 - $cpu, 2)
    Write-Report "CPU Usage: $cpu% $(if ($cpu -gt 80) { '(High)' } else { '' })" "Success"
} catch {
    Write-Report "Error: CPU analysis failed - $($_.Exception.Message)" "Error"
    Write-Audit "CPU analysis error: $($_.Exception.Message)"
    if ($Silent) { Write-Report "Skipping CPU analysis in silent mode" "Warning" }
}

    try {
        if (-not $script:cachedData["drive"]) {
            $script:cachedData["drive"] = Get-WmiObject Win32_LogicalDisk -Filter "DeviceID='C:'" -ErrorAction Stop
        }
        $drive = $script:cachedData["drive"]
        if ($drive) {
            $freePercent = [math]::Round(($drive.FreeSpace / $drive.Size) * 100, 2)
            $health.Disk = $freePercent
            Write-Report "Disk C: $freePercent% free $(if ($freePercent -lt 10) { '(Low)' } else { '' })" "Success"
            if ($freePercent -lt 10) { Run-DiskCleanup }
        }
    } catch {
        Write-Report "Error: Disk analysis failed - $($_.Exception.Message)" "Error"
        Write-Audit "Disk analysis error: $($_.Exception.Message)"
        if ($Silent) { Write-Report "Skipping disk analysis in silent mode" "Warning" }
    }

    try {
        if (-not $script:cachedData["memory"]) {
            $script:cachedData["memory"] = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
        }
        $memory = $script:cachedData["memory"]
        $ramUsedPercent = [math]::Round((($memory.TotalVisibleMemorySize - $memory.FreePhysicalMemory) / $memory.TotalVisibleMemorySize) * 100, 2)
        $health.RAM = 100 - $ramUsedPercent
        Write-Report "RAM Usage: $ramUsedPercent% $(if ($ramUsedPercent -gt 80) { '(High)' } else { '' })" "Success"
    } catch {
        Write-Report "Error: RAM analysis failed - $($_.Exception.Message)" "Error"
        Write-Audit "RAM analysis error: $($_.Exception.Message)"
        if ($Silent) { Write-Report "Skipping RAM analysis in silent mode" "Warning" }
    }

    $script:progress.StepsCompleted++
    return $health
}

function Set-RegistrySettings {
    param (
        [int]$totalSteps,
        [ref]$currentStep
    )
    Write-Report "Adjusting registry settings..." "Success"
    $regSettings = @(
        @{ Path = "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects"; Name = "VisualFXSetting"; Type = "REG_DWORD"; Value = 2; Desc = "Set visual effects to best performance" },
        @{ Path = "HKCU\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo"; Name = "Enabled"; Type = "REG_DWORD"; Value = 0; Desc = "Disable advertising ID" },
        @{ Path = "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection"; Name = "AllowTelemetry"; Type = "REG_DWORD"; Value = 0; Desc = "Disable telemetry" },
        @{ Path = "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"; Name = "Start_TrackProgs"; Type = "REG_DWORD"; Value = 0; Desc = "Disable tracking of program launches" },
        @{ Path = "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"; Name = "SystemPaneSuggestionsEnabled"; Type = "REG_DWORD"; Value = 0; Desc = "Disable system pane suggestions" },
        @{ Path = "HKCU\Software\Microsoft\InputPersonalization"; Name = "RestrictImplicitInkCollection"; Type = "REG_DWORD"; Value = 1; Desc = "Restrict implicit ink collection" },
        @{ Path = "HKCU\Software\Microsoft\InputPersonalization"; Name = "RestrictImplicitTextCollection"; Type = "REG_DWORD"; Value = 1; Desc = "Restrict implicit text collection" },
        @{ Path = "HKLM\SOFTWARE\Policies\Microsoft\Windows\System"; Name = "PublishUserActivities"; Type = "REG_DWORD"; Value = 0; Desc = "Disable user activity publishing" },
        @{ Path = "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy"; Name = "LetAppsActivateWithVoice"; Type = "REG_DWORD"; Value = 2; Desc = "Disable voice activation for apps" },
        @{ Path = "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy"; Name = "LetAppsAccessAccountInfo"; Type = "REG_DWORD"; Value = 2; Desc = "Deny apps access to account info" },
        @{ Path = "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy"; Name = "LetAppsAccessContacts"; Type = "REG_DWORD"; Value = 2; Desc = "Deny apps access to contacts" },
        @{ Path = "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy"; Name = "LetAppsAccessCalendar"; Type = "REG_DWORD"; Value = 2; Desc = "Deny apps access to calendar" },
        @{ Path = "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy"; Name = "LetAppsAccessPhone"; Type = "REG_DWORD"; Value = 2; Desc = "Deny apps access to phone" },
        @{ Path = "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy"; Name = "LetAppsAccessCallHistory"; Type = "REG_DWORD"; Value = 2; Desc = "Deny apps access to call history" },
        @{ Path = "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy"; Name = "LetAppsAccessEmail"; Type = "REG_DWORD"; Value = 2; Desc = "Deny apps access to email" },
        @{ Path = "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy"; Name = "LetAppsAccessDiagnostics"; Type = "REG_DWORD"; Value = 2; Desc = "Deny apps access to diagnostics" },
        @{ Path = "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search"; Name = "AllowCortana"; Type = "REG_DWORD"; Value = 0; Desc = "Disable Cortana" },
        @{ Path = "HKCU\System\GameConfigStore"; Name = "GameDVR_Enabled"; Type = "REG_DWORD"; Value = 0; Desc = "Disable Game DVR" },
        @{ Path = "HKCU\Control Panel\Desktop"; Name = "MenuShowDelay"; Type = "REG_SZ"; Value = "200"; Desc = "Reduce menu show delay" }
    )

    $changesMade = $false
    foreach ($setting in $regSettings) {
        # Check if the registry path exists, create it if not
        $pathExists = Test-Path $setting.Path
        if (-not $pathExists) {
            try {
                New-Item -Path $setting.Path -Force -ErrorAction Stop | Out-Null
                Write-Audit "Created registry path: $($setting.Path)"
            } catch {
                Write-Report "Warning: Failed to create path $($setting.Path) - $($_.Exception.Message)" "Warning"
                Write-Audit "Error creating path $($setting.Path): $($_.Exception.Message)"
            }
        }

        # Check current value
        $currentValue = Get-ItemProperty -Path $setting.Path -Name $setting.Name -ErrorAction SilentlyContinue
        $valueExists = $null -ne $currentValue
        $valueMatches = $valueExists -and ($currentValue.$($setting.Name) -eq $setting.Value)

        if ($valueMatches) {
            Write-Report "Skipped $($setting.Desc) - already set to $($setting.Value)" "Warning"
            Write-Audit "Skipped $($setting.Path)\$($setting.Name) - already set"
        } else {
            # Build and execute the reg add command
            $regCommand = "reg add `"$($setting.Path)`" /v `"$($setting.Name)`" /t $($setting.Type) /d $($setting.Value) /f"
            try {
                Write-Audit "Executing: $regCommand"
                Start-Process "cmd.exe" -ArgumentList "/c $regCommand" -NoNewWindow -Wait -ErrorAction Stop
                Write-Report "Applied: $($setting.Desc)" "Success"
                Write-Audit "Set $($setting.Path)\$($setting.Name) to $($setting.Value)"
                $changesMade = $true
            } catch {
                Write-Report "Error: Failed to set $($setting.Desc) - $($_.Exception.Message)" "Error"
                Write-Audit "Error setting $($setting.Path)\$($setting.Name): $($_.Exception.Message)"
                if (-not $Silent -and (Confirm-Action "Retry $($setting.Desc)?")) {
                    try {
                        Start-Process "cmd.exe" -ArgumentList "/c $regCommand" -NoNewWindow -Wait -ErrorAction Stop
                        Write-Report "Applied on retry: $($setting.Desc)" "Success"
                        Write-Audit "Set $($setting.Path)\$($setting.Name) to $($setting.Value) on retry"
                        $changesMade = $true
                    } catch {
                        Write-Report "Error: Retry failed for $($setting.Desc) - $($_.Exception.Message)" "Error"
                        Write-Audit "Retry failed for $($setting.Path)\$($setting.Name): $($_.Exception.Message)"
                    }
                }
            }
        }
    }

    if (-not $changesMade) {
        Write-Report "No registry changes needed - all settings already optimized" "Success"
    }
    
    # Increment the current step if provided
    if ($currentStep) {
        $currentStep.Value++
    }

    return $true
}

function Disable-StartupPrograms {
    param (
        [int]$totalSteps,
        [ref]$currentStep
    )
    Write-Report "Disabling startup programs..." "Success"
    $changesMade = $false
    try {
        # Get all registry values under the Run key
        $startupItems = Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run" -ErrorAction Stop
        # Get the property names excluding PowerShell metadata
        $valueNames = $startupItems | Get-Member -MemberType NoteProperty | Where-Object { $_.Name -notin @("PSChildName", "PSDrive", "PSParentPath", "PSPath", "PSProvider") } | Select-Object -ExpandProperty Name

        if ($valueNames) {
            foreach ($name in $valueNames) {
                if ($name -notin @("SecurityHealth", "ctfmon")) {
                    Write-Report "Disabling startup program: $name" "Success"
                    Write-Audit "Removing startup: $name"
                    Remove-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run" -Name $name -ErrorAction Stop
                    $changesMade = $true
                } else {
                    Write-Report "Skipped essential startup program: $name" "Warning"
                }
            }
        } else {
            Write-Report "No startup programs found in HKLM:\Software\Microsoft\Windows\CurrentVersion\Run" "Warning"
        }

        if (-not $changesMade -and $valueNames) {
            Write-Report "No unnecessary startup programs found to disable" "Success"
        }
    } catch {
        Write-Report "Error: Failed to disable startup programs - $($_.Exception.Message)" "Error"
        Write-Audit "Error disabling startup: $($_.Exception.Message)"
        if ($Silent) { 
            Write-Report "Skipping startup disable in silent mode" "Warning" 
        }
        return $false
    }

    if ($currentStep) {
        $currentStep.Value++
    }
    return $true
}

function Disable-Animations {
    param ($totalSteps, [ref]$currentStep)
    Write-Report "Disabling animations..." "Success"
    $targetValue = [byte[]](0x90,0x12,0x03,0x80,0x10,0x00,0x00,0x00)
    $currentValue = Get-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "UserPreferencesMask" -ErrorAction SilentlyContinue
    if ($currentValue -and [System.Linq.Enumerable]::SequenceEqual($currentValue.UserPreferencesMask, $targetValue)) {
        Write-Report "Animations already disabled - skipping" "Warning"
        return $true
    }
    try {
        Write-Audit "Setting UserPreferencesMask to disable animations"
        Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "UserPreferencesMask" -Value $targetValue -Force -ErrorAction Stop
        Write-Report "Animations disabled successfully" "Success"
    } catch {
        Write-Report "Error: Failed to disable animations - $($_.Exception.Message)" "Error"
        Write-Audit "Error disabling animations: $($_.Exception.Message)"
        if ($Silent) { Write-Report "Skipping animation disable in silent mode" "Warning" }
        return $false
    }
    return $true
}

function Set-PowerSettings {
    param ($totalSteps, [ref]$currentStep)
    Write-Report "Optimizing power settings..." "Success"
    $highPerfPlan = "8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c"
    $currentPlan = (powercfg /getactivescheme).Split()[3]
    if ($currentPlan -eq $highPerfPlan) {
        Write-Report "Power plan already set to High Performance - skipping" "Warning"
        return $true
    }
    try {
        Write-Audit "Setting power plan to High Performance"
        powercfg /setactive $highPerfPlan
        Write-Report "Power plan set to High Performance" "Success"
    } catch {
        Write-Report "Error: Failed to optimize power settings - $($_.Exception.Message)" "Error"
        Write-Audit "Error setting power plan: $($_.Exception.Message)"
        if ($Silent) { Write-Report "Skipping power optimization in silent mode" "Warning" }
        return $false
    }
    return $true
}

function Adjust-Performance {
    Write-Report "Optimizing performance..." "Success"
    Show-Progress -CurrentStep 3 -TotalSteps 4 -Activity "Optimizing performance"
    if (Confirm-Action "Apply performance optimizations (registry, startups, animations, power)?") {
        $totalSteps = 4
        $currentStep = 0
        $regBackupDir = Join-Path $OutputPath "RegistryBackup_$timestamp"
        New-Item -Path $regBackupDir -ItemType Directory -Force | Out-Null
        Write-Report "Backing up registry to $regBackupDir..." "Success"
        Write-Audit "Backing up registry to $regBackupDir"
        try {
        reg export HKCU\Software\Microsoft\Windows\CurrentVersion "$regBackupDir\HKCU.reg" /y 2>$null
        reg export HKLM\SOFTWARE\Policies\Microsoft\Windows "$regBackupDir\HKLM_Policies.reg" /y 2>$null
        reg export HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run "$regBackupDir\HKLM_Run.reg" /y 2>$null
        Write-Report "Registry backup completed" "Success"
        } catch {
    Write-Report "Warning: Failed to backup registry - $($_.Exception.Message)" "Warning"
}

        Write-Report "`nStarting performance optimizations:" "Success"
        $currentStep++
        if (Set-RegistrySettings -totalSteps $totalSteps -currentStep ([ref]$currentStep)) {
            Write-Report "Registry optimization completed" "Success"
        }
        $currentStep++
        if (Disable-StartupPrograms -totalSteps $totalSteps -currentStep ([ref]$currentStep)) {
            Write-Report "Startup program optimization completed" "Success"
        }
        $currentStep++
        if (Disable-Animations -totalSteps $totalSteps -currentStep ([ref]$currentStep)) {
            Write-Report "Animation optimization completed" "Success"
        }
        $currentStep++
        if (Set-PowerSettings -totalSteps $totalSteps -currentStep ([ref]$currentStep)) {
            Write-Report "Power settings optimization completed" "Success"
        }
    }

    # Ask once for stopping services, outside any loop
    $stopServices = Confirm-Action "Stop unnecessary background services (including news notifications)?"
    if ($stopServices) {
        $services = @("XblAuthManager", "WbioSrvc", "SysMain", "DiagTrack", "MapsBroker", "WMPNetworkSvc", "RetailDemo", "WpnUserService")
        $totalServices = $services.Count
        $currentService = 0
        $serviceBackup = @{}

        Write-Report "`nStopping unnecessary services:" "Success"
        foreach ($svc in $services) {
            $currentService++
            Write-Report "Processing service $svc (Step $currentService of $totalServices)..." "Success"
            $service = Get-Service -Name $svc -ErrorAction SilentlyContinue
            if ($service) {
                $dependents = Get-Service -Name $svc -DependentServices | Where-Object { $_.Status -eq "Running" }
                if ($dependents) {
                    Write-Report "Warning: $svc has running dependents: $($dependents.Name -join ', '). Skipping." "Warning"
                    Write-Audit "Skipped $svc due to dependents: $($dependents.Name -join ', ')"
                    continue
                }
                $serviceBackup[$svc] = $service.StartType
                if ($service.StartType -ne "Disabled") {
                    try {
                        Write-Audit "Stopping and disabling service: $svc (Original state: $($service.StartType))"
                        Stop-Service -Name $svc -Force -ErrorAction Stop
                        Set-Service -Name $svc -StartupType Disabled -ErrorAction Stop
                        Write-Report "Stopped and disabled service: $svc" "Success"
                    } catch {
                        Write-Report "Warning: Failed to stop ${svc} - $($_.Exception.Message)" "Warning"
                        Write-Audit "Error stopping ${svc}: $($_.Exception.Message)"
                        $choice = if ($Silent) { "s" } else { Read-Host "Retry (r) or Skip (s)? [r/s]" }
                        if ($choice -eq "r") {
                            try {
                                Stop-Service -Name $svc -Force -ErrorAction Stop
                                Set-Service -Name $svc -StartupType Disabled -ErrorAction Stop
                                Write-Report "Stopped and disabled ${svc} on retry" "Success"
                            } catch {
                                Write-Report "Error: Retry failed for ${svc} - $($_.Exception.Message)" "Error"
                            }
                        } else {
                            Write-Report "Skipped ${svc}" "Warning"
                        }
                    }
                } else {
                    Write-Report "Service $svc already disabled - skipping" "Warning"
                }
            } else {
                Write-Report "Service $svc not found - skipping" "Warning"
            }
        }
        Write-Audit "Service states backed up: $($serviceBackup | ConvertTo-Json -Compress)"
        Write-Report "Service optimization completed" "Success"
    }

    $script:progress.StepsCompleted++
    Write-Report "`nPerformance optimization finished" "Success"
}

function Run-DiskCleanup {
    Write-Report "Cleaning disk..." "Success"
    if (Confirm-Action "Perform disk cleanup and optimization?") {
        try {
            $cleanupRegPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches"
            $cleanupCategories = @(
                "Active Setup Temp Folders", "BranchCache", "Compress Old Files", "Downloaded Program Files",
                "Internet Cache Files", "Memory Dump Files", "Offline Pages Files", "Old ChkDsk Files",
                "Previous Installations", "Recycle Bin", "Service Pack Cleanup", "Setup Log Files",
                "System error memory dump files", "System error minidump files", "Temporary Files",
                "Temporary Setup Files", "Thumbnail Cache", "Update Cleanup", "Windows Error Reporting Files"
            )
            foreach ($category in $cleanupCategories) {
                $path = "$cleanupRegPath\$category"
                if (-not (Test-Path $path)) { New-Item -Path $path -Force -ErrorAction Stop | Out-Null }
                Set-ItemProperty -Path $path -Name "StateFlags0001" -Value 2 -Type DWord -Force -ErrorAction Stop
                Write-Audit "Enabled cleanup category: $category"
            }
            Write-Audit "Running cleanmgr.exe /sagerun:1"
            Start-Process "cleanmgr.exe" -ArgumentList "/sagerun:1" -Wait -NoNewWindow -ErrorAction Stop
            Write-Audit "Optimizing C: drive"
            Optimize-Volume -DriveLetter C -Defrag -Verbose -ErrorAction Stop
            Write-Report "Disk cleanup and optimization completed" "Success"
        } catch {
            Write-Report "Error: Disk cleanup failed - $($_.Exception.Message)" "Error"
            Write-Audit "Error during cleanup: $($_.Exception.Message)"
            if ($Silent) { Write-Report "Skipping cleanup in silent mode" "Warning" }
            elseif (Confirm-Action "Retry?") { Run-DiskCleanup } else { Write-Report "Skipped cleanup" "Warning" }
        }
    }
}

function Uninstall-Apps {
    Write-Report "Removing applications..." "Success"
    Show-Progress -CurrentStep 4 -TotalSteps 4 -Activity "Processing application removal"
    try {
        $script:installedApps = Get-AppxPackage -AllUsers -ErrorAction Stop | Where-Object { $_.IsFramework -eq $false -and $_.SignatureKind -ne "System" } | Select-Object Name, PackageFullName
    } catch {
        Write-Report "Error: Failed to list installed applications - $($_.Exception.Message)" "Error"
        return
    }
    $defaultApps = $config.AppsToRemove

    $invalidApps = $defaultApps | Where-Object { -not ($script:installedApps.Name -contains $_) }
    if ($invalidApps) {
        Write-Report "Warning: These applications in config.json are not installed: $($invalidApps -join ', ')" "Warning"
        Write-Audit "Invalid applications in config: $($invalidApps -join ', ')"
    }

    Write-Report "Applications available for removal:" "Success"
    for ($i = 0; $i -lt $defaultApps.Count; $i++) {
        $app = $defaultApps[$i]
        $installed = $script:installedApps | Where-Object { $_.Name -eq $app }
        if ($installed) {
            Write-Host "$($i + 1). $app (Installed)" -ForegroundColor Green
        } else {
            Write-Host "$($i + 1). $app (Not installed)" -ForegroundColor Yellow
        }
    }

    $validInput = $false
    while (-not $validInput) {
        Write-Host "Enter numbers (e.g., '1 3 5') or press Enter for defaults:" -ForegroundColor Magenta

        $selection = if ($Silent) { "" } else { Read-Host -Prompt "Selection" }
        
        if ([string]::IsNullOrWhiteSpace($selection)) {
            $appsToRemove = $defaultApps | Where-Object { $script:installedApps.Name -contains $_ }
            $validInput = $true
        } else {
            $numbers = $selection -split "\s+" | Where-Object { $_ -ne "" }
            $appsToRemove = @()
            $invalid = $false

            foreach ($num in $numbers) {
                if (-not ($num -match "^\d+$")) {
                    Write-Report "Warning: '$num' is not a valid number. Try again." "Warning"
                    $invalid = $true
                    break
                }
                $index = [int]$num - 1
                if ($index -lt 0 -or $index -ge $defaultApps.Count) {
                    Write-Report "Warning: '$num' is out of range (1-$($defaultApps.Count)). Try again." "Warning"
                    $invalid = $true
                    break
                }
                $appsToRemove += $defaultApps[$index]
            }

            if (-not $invalid) {
                $validInput = $true
            }
        }
    }

    if ($appsToRemove.Count -eq 0) {
        Write-Report "No applications selected for removal" "Warning"
        return
    }

    if (Confirm-Action "Remove these applications: $($appsToRemove -join ', ')?") {
        $totalApps = $appsToRemove.Count
        $currentApp = 0
        foreach ($app in $appsToRemove) {
            $currentApp++
            Write-Report "Removing application $app (Step $currentApp of $totalApps)..." "Success"
            $package = $script:installedApps | Where-Object { $_.Name -eq $app }
            if ($package) {
                try {
                    Write-Audit "Removing application: $app"
                    # Use Start-Process with powershell.exe to ensure synchronous removal
                    $removeCommand = "Remove-AppxPackage -Package `"$($package.PackageFullName)`" -ErrorAction Stop"
                    Start-Process "powershell.exe" -ArgumentList "-NoProfile -Command $removeCommand" -Wait -NoNewWindow -ErrorAction Stop
                    Write-Report "Removed ${app}" "Success"
                    $script:progress.AppsRemoved++
                } catch {
                    Write-Report "Warning: Failed to remove ${app} - $($_.Exception.Message)" "Warning"
                    Write-Audit "Error removing ${app}: $($_.Exception.Message)"
                    $choice = if ($Silent) { "s" } else { Read-Host "Retry (r) or Skip (s)? [r/s]" }
                    if ($choice -eq "r") {
                        try {
                            Start-Process "powershell.exe" -ArgumentList "-NoProfile -Command $removeCommand" -Wait -NoNewWindow -ErrorAction Stop
                            Write-Report "Removed ${app} on retry" "Success"
                            $script:progress.AppsRemoved++
                        } catch {
                            Write-Report "Error: Retry failed for ${app} - $($_.Exception.Message)" "Error"
                        }
                    } else {
                        Write-Report "Skipped ${app}" "Warning"
                    }
                }
            }
        }

        if ($script:progress.AppsRemoved -gt 0) {
            Write-Host "Restart required to complete application removal." -ForegroundColor Yellow
            $restartChoice = if ($Silent) { "l" } else { Read-Host "Restart now (r) or later (l)? [r/l]" }
            if ($restartChoice -match "^[Rr]$") {
                Write-Report "Restarting system..." "Success"
                Write-Audit "Initiating system restart"
                Flush-Buffers
                Restart-Computer -Force
            } else {
                Write-Report "Please restart later to finalize changes." "Warning"
            }
        }
    }
    $script:progress.StepsCompleted++
}

function Configure-Apps {
    Write-Report "`nConfiguration Settings" "Success"
    Write-Host "Current applications to remove: $($config.AppsToRemove -join ', ')" -ForegroundColor Green
    Write-Host "Choose mode: 1) Basic, 2) Advanced, or press Enter to add manually:" -ForegroundColor Magenta

    $mode = if ($Silent) { "2" } else { Read-Host }
    if ($mode -eq "1") {
        $config.AppsToRemove = @("Microsoft.SkypeApp", "Microsoft.Teams", "Microsoft.GetHelp", "Microsoft.BingNews")
        Write-Report "Set to Basic mode" "Success"
        Write-Audit "Config set to Basic mode: $($config.AppsToRemove -join ', ')"
    } elseif ($mode -eq "2") {
        $config.AppsToRemove = @(
            "Microsoft.SkypeApp", "Microsoft.Teams", "Microsoft.XboxApp", "Microsoft.MixedReality.Portal",
            "Microsoft.GetHelp", "Microsoft.People", "Microsoft.WindowsFeedbackHub", "Microsoft.YourPhone",
            "Microsoft.ZuneMusic", "Microsoft.ZuneVideo", "Microsoft.BingNews", "Microsoft.BingWeather",
            "Microsoft.MicrosoftSolitaireCollection", "Microsoft.3DBuilder", "Microsoft.WindowsMaps",
            "Microsoft.Getstarted", "Microsoft.Messaging", "Microsoft.WindowsCamera"
        )
        Write-Report "Set to Advanced mode" "Success"
        Write-Audit "Config set to Advanced mode: $($config.AppsToRemove -join ', ')"
    } else {
        Write-Host "Add an application (e.g., Microsoft.SkypeApp) or press Enter to skip:" -ForegroundColor Magenta

        $newApp = if ($Silent) { "" } else { Read-Host }
        if ($newApp) {
            if ($newApp -match "^[a-zA-Z0-9\._]+$") {
                $config.AppsToRemove += $newApp
                Write-Audit "Added application to config: $newApp"
                Write-Report "Added $newApp to removal list" "Success"
            } else {
                Write-Report "Error: Invalid application name '$newApp' (use letters, numbers, dots only)" "Warning"
            }
        }
    }
    Write-Report "Configuration updated" "Success"
    if (-not $Portable) {
        try {
            $config | ConvertTo-Json | Set-Content $ConfigFile -ErrorAction Stop
        } catch {
            Write-Report "Warning: Failed to save config - $($_.Exception.Message)" "Warning"
        }
    }
}

function Repair-System {
    Write-Report "`nRepair System Menu" "Success"
    Write-Host "Select an option:" -ForegroundColor Green
    Write-Host "1. Scan and repair system files" -ForegroundColor Green
    Write-Host "2. Repair corrupted Windows files" -ForegroundColor Green
    Write-Host "3. Fix Windows Update issues" -ForegroundColor Green
    Write-Host "4. Repair disk errors" -ForegroundColor Green
    Write-Host "5. Return to main menu" -ForegroundColor Green
    $choice = if ($Silent) { "5" } else { Read-Host "Choose (1-5)" }

    switch ($choice) {
        "1" {
            Write-Report "Scanning and repairing system files..." "Success"
            try {
                Write-Audit "Running sfc /scannow"
                Start-Process "cmd.exe" -ArgumentList "/c sfc /scannow" -NoNewWindow -Wait -ErrorAction Stop
                Write-Report "System file scan and repair completed" "Success"
            } catch {
                Write-Report "Error: System file repair failed - $($_.Exception.Message)" "Error"
                Write-Audit "SFC error: $($_.Exception.Message)"
            }
        }
        "2" {
            Write-Report "Repairing corrupted Windows files..." "Success"
            try {
                Write-Audit "Running DISM /Online /Cleanup-Image /RestoreHealth"
                Start-Process "cmd.exe" -ArgumentList "/c dism /online /cleanup-image /restorehealth" -NoNewWindow -Wait -ErrorAction Stop
                Write-Report "Windows file repair completed" "Success"
            } catch {
                Write-Report "Error: Windows file repair failed - $($_.Exception.Message)" "Error"
                Write-Audit "DISM error: $($_.Exception.Message)"
            }
        }
        "3" {
            Write-Report "Fixing Windows Update issues..." "Success"
            try {
                Write-Audit "Stopping Windows Update services"
                Start-Process "cmd.exe" -ArgumentList "/c net stop wuauserv" -NoNewWindow -Wait -ErrorAction Stop
                Start-Process "cmd.exe" -ArgumentList "/c net stop bits" -NoNewWindow -Wait -ErrorAction Stop
                Write-Audit "Starting Windows Update services"
                Start-Process "cmd.exe" -ArgumentList "/c net start wuauserv" -NoNewWindow -Wait -ErrorAction Stop
                Start-Process "cmd.exe" -ArgumentList "/c net start bits" -NoNewWindow -Wait -ErrorAction Stop
                Write-Report "Windows Update services reset" "Success"
            } catch {
                Write-Report "Error: Failed to reset Windows Update services - $($_.Exception.Message)" "Error"
                Write-Audit "Windows Update fix error: $($_.Exception.Message)"
            }
        }
        "4" {
            Write-Report "Repairing disk errors..." "Success"
            try {
                Write-Audit "Running chkdsk C: /f /r"
                Start-Process "cmd.exe" -ArgumentList "/c chkdsk C: /f /r" -NoNewWindow -Wait -ErrorAction Stop
                Write-Report "Disk error repair scheduled (may require restart)" "Success"
            } catch {
                Write-Report "Error: Disk repair failed - $($_.Exception.Message)" "Error"
                Write-Audit "Disk repair error: $($_.Exception.Message)"
            }
        }
        "5" { Write-Report "Returning to main menu..." "Success" }
        default { Write-Report "Error: Select 1-5 to proceed" "Warning"; Repair-System }
    }
}

function Show-Help {
    Write-Host "`nHelp Menu" -ForegroundColor Cyan
    Write-Host "1. Check PC: View system health statistics." -ForegroundColor Green
    Write-Host "2. Speed Up: Optimize performance settings and services." -ForegroundColor Green
    Write-Host "3. Remove Apps: Uninstall specified applications." -ForegroundColor Green
    Write-Host "4. Configure Apps: Configure application removal list." -ForegroundColor Green
    Write-Host "5. Repair System: Repair system issues (files, updates, disk)." -ForegroundColor Green
    Write-Host "6. Exit: Close the script." -ForegroundColor Green
    Write-Host "Press Enter to return..." -ForegroundColor Yellow
    if (-not $Silent) { Read-Host }
}

function Show-Menu {
    $retryCount = 0
    $maxRetries = 3
    while ($retryCount -lt $maxRetries) {
    Write-Host "`nPCTurboBoost Menu v$script:Version" -ForegroundColor Cyan
    Write-Host "1. Check PC" -ForegroundColor Green
    Write-Host "2. Speed Up" -ForegroundColor Green
    Write-Host "3. Remove Apps" -ForegroundColor Green
    Write-Host "4. Configure Apps" -ForegroundColor Green
    Write-Host "5. Repair System" -ForegroundColor Green
    Write-Host "6. Exit" -ForegroundColor Green
    Write-Host "Type 'help' for instructions." -ForegroundColor Yellow
    $choice = if ($Silent) { "6" } else { Read-Host "Select (1-6)" }
    if ($choice -eq "help") { Show-Help; continue }
    if ($choice -match "^[1-6]$") { return $choice }
        Write-Report "Error: Select 1-6 to proceed" "Warning"
        $retryCount++
    }
    Write-Report "Too many invalid inputs. Exiting..." "Error"
    return "6"
}

while ($true) {
    $choice = Show-Menu
    switch ($choice) {
        "1" { Get-SystemInfo; $health = Run-Diagnostics }
        "2" { Adjust-Performance }
        "3" { Uninstall-Apps }
        "4" { Configure-Apps }
        "5" { Repair-System }
        "6" { Write-Report "Script completed. Exiting..." "Success"; break }
    }
    if ($choice -eq "6") { break }
    Write-Host "Task completed. Press Enter to continue..." -ForegroundColor Magenta
    if (-not $Silent) { Read-Host }
}

# Summary Report
Write-Host "`nOptimization Summary" -ForegroundColor Cyan
$summary = @(
    [PSCustomObject]@{ "Metric" = "Steps Completed"; "Value" = "$($script:progress.StepsCompleted)/4" },
    [PSCustomObject]@{ "Metric" = "Apps Removed"; "Value" = $script:progress.AppsRemoved }
)
if ($health) {
    $score = [math]::Round(($health.CPU + $health.Disk + $health.RAM) / 3, 2)
    $summary += [PSCustomObject]@{ "Metric" = "Health Score"; "Value" = "$score/100 (CPU: $($health.CPU), Disk: $($health.Disk), RAM: $($health.RAM))" }
}
$summary | Format-Table -AutoSize | Out-String | Write-Host -ForegroundColor Green
if (-not $Portable) {
    Write-Report "Report saved to: $outputFile" "Success"
    Write-Report "Audit log saved to: $auditLog" "Success"
}
Flush-Buffers