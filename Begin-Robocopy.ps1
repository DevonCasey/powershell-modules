# Robocopy Script with Interactive Input
# Parameters for source and destination directories
param(
    [string]$Source,
    [string]$Destination,
    [switch]$UseAdmin
)

# Enhanced logging function
function Write-Status {
    param([string]$Message, [string]$Level = "INFO")
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Host "[$Timestamp] [$Level] $Message" -ForegroundColor $(
        switch ($Level) {
            "ERROR" { "Red" }
            "WARNING" { "Yellow" }
            "SUCCESS" { "Green" }
            default { "White" }
        }
    )
}

# Ensures the script gets ran as admin, sometimes needed.
if ($UseAdmin -and -not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Status "Admin privileges required for proper ACL handling. Restarting as administrator..." "WARNING"
    $Params = "-NoProfile -ExecutionPolicy Bypass -File `"$($MyInvocation.MyCommand.Path)`""
    if ($Source) { $Params += " -Source `"$Source`"" }
    if ($Destination) { $Params += " -Destination `"$Destination`"" }
    $Params += " -UseAdmin"
    Start-Process -FilePath "powershell.exe" -ArgumentList $Params -Verb RunAs
    exit
}

$ScriptName = [System.IO.Path]::GetFileNameWithoutExtension($MyInvocation.MyCommand.Name)
$LogDir = "C:\Users\$User\Documents\Logs\$ScriptName"
if (-not (Test-Path $LogDir)) {
    New-Item -Path $LogDir -ItemType Directory -Force | Out-Null
    Write-Status "Created log directory: $LogDir" "INFO"
}
$Timestamp = Get-Date -Format "MM-dd-yyyy_HH-MM-ss"
$LogFile = Join-Path -Path $LogDir -ChildPath "robocopy-$Timestamp.log"

try {
    Start-Transcript -Path $LogFile -Append
    Write-Status "Started transcript logging: $LogFile" "INFO"
}
catch {
    Write-Status "Failed to start transcript logging: $($_.Exception.Message)" "WARNING"
}

# Get source and destination from user input if not provided as parameters
if (-not $Source -or -not $Destination) {
    Write-Status "Starting interactive mode - gathering source and destination paths" "INFO"
    Write-Host "=" * 50
    
    if (-not $Source) {
        Write-Host "Enter source directory path:" -ForegroundColor Yellow
        Write-Host "Examples: C:\Source, \\server\share, V:\" -ForegroundColor Gray
        do {
            $Source = Read-Host "Source"
            if (-not $Source -or $Source.Trim() -eq "") {
                Write-Status "Source directory is required!" "ERROR"
            }
            elseif (-not (Test-Path $Source)) {
                Write-Status "Source directory does not exist: $Source" "ERROR"
                $Source = $null
            }
            else {
                Write-Status "Source directory validated: $Source" "SUCCESS"
            }
        } while (-not $Source)
    }
    
    if (-not $Destination) {
        Write-Host "`nEnter destination directory path:" -ForegroundColor Yellow
        Write-Host "Examples: C:\Destination, \\server\backup, E:\Backup" -ForegroundColor Gray
        do {
            $Destination = Read-Host "Destination"
            if (-not $Destination -or $Destination.Trim() -eq "") {
                Write-Status "Destination directory is required!" "ERROR"
            }
            else {
                Write-Status "Destination directory set: $Destination" "SUCCESS"
            }
        } while (-not $Destination)
    }
    Write-Host "`nConfiguration Summary:" -ForegroundColor Green
    Write-Host "Source:      $Source" -ForegroundColor White
    Write-Host "Destination: $Destination" -ForegroundColor White
    Write-Host "Log File:    $LogFile" -ForegroundColor White
    
    $confirm = Read-Host "`nProceed with robocopy? (y/N)"
    if ($confirm -notmatch "^[yY]") {
        Write-Status "Operation cancelled by user." "WARNING"
        exit 0
    }
}

Write-Status "Starting robocopy operation from '$Source' to '$Destination'" "INFO"
Write-Status "Robocopy parameters: /MIR /copy:DAT /Z /MT:16 /R:2 /W:5" "INFO"

# Execute robocopy command
$RobocopyStart = Get-Date
robocopy $Source $Destination `
    /MIR /copy:DAT /Z /MT:16 /R:2 /W:5 `
    /TEE /E

$RobocopyEnd = Get-Date
$Duration = $RobocopyEnd - $RobocopyStart
$ExitCode = $LASTEXITCODE

# Robocopy exit codes interpretation
$ExitMessage = switch ($ExitCode) {
    0 { "No files were copied. No failure was encountered. No files were mismatched." }
    1 { "All files were copied successfully." }
    2 { "There are some additional files in the destination directory that are not present in the source directory." }
    3 { "Some files were copied. Additional files were present." }
    4 { "Some Mismatched files or directories were detected." }
    5 { "Some files were copied. Some files were mismatched." }
    6 { "Additional files and mismatched files exist." }
    7 { "Files were copied, a file mismatch was present, and additional files were present." }
    8 { "Several files did not copy." }
    default { "Unknown exit code: $ExitCode" }
}

if ($ExitCode -le 3) {
    Write-Status "Robocopy completed successfully (Exit code: $ExitCode) - $ExitMessage" "SUCCESS"
}
elseif ($ExitCode -le 7) {
    Write-Status "Robocopy completed with warnings (Exit code: $ExitCode) - $ExitMessage" "WARNING"
}
else {
    Write-Status "Robocopy encountered errors (Exit code: $ExitCode) - $ExitMessage" "ERROR"
}

Write-Status "Operation duration: $($Duration.ToString('hh\:mm\:ss'))" "INFO"
Write-Status "Log file location: $LogFile" "INFO"

# Stop PowerShell transcript logging
try {
    Stop-Transcript
    Write-Status "Stopped transcript logging: $LogFile" "INFO"
}
catch {
    Write-Status "Failed to stop transcript logging: $($_.Exception.Message)" "WARNING"
}
