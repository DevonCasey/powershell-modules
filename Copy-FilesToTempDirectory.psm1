<#
.SYNOPSIS
    Copies files to the C:\tmp directory for installation or processing.

.DESCRIPTION
    This module provides functionality to copy installation files to the C:\tmp directory,
    ensuring clean installations and avoiding path-related issues.

.PARAMETER SourceFiles
    Hashtable containing source and destination file mappings.

.PARAMETER TempDirectory
    Optional. The temporary directory path where files will be copied. Defaults to "C:\tmp".

.EXAMPLE
    $Files = @{
        "C:\source\installer.msi" = "installer.msi"
        "C:\source\config.conf" = "config.conf"
    }
    Copy-FilesToTempDirectory -SourceFiles $Files

.NOTES
    - Creates C:\tmp directory if it doesn't exist
    - Overwrites existing files in the temp directory
    - Uses Write-Status function for consistent logging
    - Returns $true on success, $false on failure
#>

function Copy-FilesToTempDirectory {
    [CmdletBinding()]
    param(        [Parameter(Mandatory = $true)]
        [hashtable]$SourceFiles,
        
        [Parameter(Mandatory = $false)]
        [string]$TempDirectory = "C:\tmp"
    )
    
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
    try {
        Write-Status "Setting up temporary directory and copying installation files..."
        
        # Create temp directory if it doesn't exist
        if (-not (Test-Path $TempDirectory)) {
            Write-Status "Creating temporary directory: $TempDirectory"
            New-Item -Path $TempDirectory -ItemType Directory -Force | Out-Null
        }
        else {
            Write-Status "Temporary directory already exists: $TempDirectory" "INFO"
        }
        
        # Copy each file
        foreach ($SourcePath in $SourceFiles.Keys) {
            $DestinationFileName = $SourceFiles[$SourcePath]
            $DestinationPath = Join-Path $TempDirectory $DestinationFileName
            
            if (Test-Path $SourcePath) {
                $FileName = Split-Path -Leaf $SourcePath
                Write-Status "Copying $FileName to temp directory..."
                Copy-Item -Path $SourcePath -Destination $DestinationPath -Force
                Write-Status "$FileName copied: $DestinationPath" "SUCCESS"            
            }
            else {
                Write-Status "Source file not found: $SourcePath" "ERROR"
                return $false
            }
        }
        
        return $true
    }
    catch {
        Write-Status "Failed to copy files to temp directory: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

Export-ModuleMember -Function Copy-FilesToTempDirectory
