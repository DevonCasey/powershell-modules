# Write-Status.psm1
# WCL Public PC Scripts - Write-Status Module
# This module provides enhanced logging capabilities with timestamps and color-coded output

function Write-Status {
    <#
    .SYNOPSIS
        Writes timestamped log messages with color-coded severity levels.
    
    .DESCRIPTION
        This function provides enhanced logging capabilities with timestamps and color-coded
        output based on the severity level. It's used throughout WCL scripts for consistent
        logging and informing staff of a scripts success.
    
    .PARAMETER Message
        The message to display and log.
    
    .PARAMETER Level
        The severity level of the message. Valid values are:
        - INFO (default): White text
        - SUCCESS: Green text
        - WARNING: Yellow text
        - ERROR: Red text
    
    .EXAMPLE
        Write-Status "Starting installation..." "INFO"
        Displays a timestamped info message in white.
    
    .EXAMPLE
        Write-Status "Operation completed successfully" "SUCCESS"
        Displays a timestamped success message in green.
    
    .EXAMPLE
        Write-Status "Warning: Configuration file not found" "WARNING"
        Displays a timestamped warning message in yellow.
    
    .EXAMPLE
        Write-Status "Error: Installation failed" "ERROR"
        Displays a timestamped error message in red.
    #>
    
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,
        
        [Parameter(Mandatory = $false)]
        [ValidateSet("INFO", "SUCCESS", "WARNING", "ERROR")]
        [string]$Level = "INFO"
    )
    
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $Color = switch ($Level) {
        "ERROR" { "Red" }
        "WARNING" { "Yellow" }
        "SUCCESS" { "Green" }
        default { "White" }
    }
    
    Write-Host "[$Timestamp] [$Level] $Message" -ForegroundColor $Color
}

# Export the function to make it available when the module is imported
Export-ModuleMember -Function Write-Status
