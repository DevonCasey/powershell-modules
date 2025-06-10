<#
.SYNOPSIS
    Removes all temporary files from C:\tmp directory.

.DESCRIPTION
    This module provides functionality to clean up all temporary files from the 
    C:\tmp directory after installation or processing operations.

.PARAMETER TempDirectory
    Optional. The temporary directory to clean. Defaults to "C:\tmp".

.EXAMPLE
    Remove-TempFiles

.EXAMPLE
    Remove-TempFiles -TempDirectory "C:\temp"

.NOTES
    - Removes all files and subdirectories from the temp directory
    - Provides detailed logging of cleanup operations
    - Uses Write-Status function for consistent logging
#>

function Remove-TempFiles {
    [CmdletBinding()]
    param(
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
    
    Write-Status "Cleaning up temporary directory: $TempDirectory"
    
    try {
        if (Test-Path $TempDirectory) {
            $Items = Get-ChildItem -Path $TempDirectory -Force
            $ItemCount = ($Items | Measure-Object).Count
            
            if ($ItemCount -gt 0) {
                Write-Status "Found $ItemCount item(s) to remove in $TempDirectory" "INFO"
                
                foreach ($Item in $Items) {
                    Remove-Item -Path $Item.FullName -Recurse -Force
                    Write-Status "Removed: $($Item.Name)" "INFO"
                }
                
                Write-Status "Successfully removed all items from temporary directory" "SUCCESS"
            }
            else {
                Write-Status "Temporary directory is already empty" "INFO"
            }
        }
        else {
            Write-Status "Temporary directory does not exist: $TempDirectory" "INFO"
        }
        
        Write-Status "Temporary file cleanup completed" "SUCCESS"
        return $true
    }
    catch {
        Write-Status "Failed to clean up temporary files: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

Export-ModuleMember -Function Remove-TempFiles
