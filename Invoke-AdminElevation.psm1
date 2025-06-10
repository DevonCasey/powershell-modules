# Invoke-AdminElevation.psm1
# WCL Public PC Scripts - Invoke-AdminElevation Module
# This module provides UAC handling with infinite loop protection

# Import required modules for Write-Status and Send-AnyKeyAndExit
Import-Module (Join-Path $PSScriptRoot "Write-Status.psm1") -Force
Import-Module (Join-Path $PSScriptRoot "Send-AnyKeyAndExit.psm1") -Force

function Invoke-AdminElevation {
    <#
    .SYNOPSIS
        Ensures the script is running with administrator privileges, with infinite loop prevention.
    
    .DESCRIPTION
        Checks if the current PowerShell session is running as administrator. If not, attempts to restart
        the script with elevated privileges using UAC. Includes safeguards to prevent infinite loops
        when UAC is disabled or elevation fails.
    
    .PARAMETER ScriptPath
        The full path to the script that needs elevation. Usually $MyInvocation.MyCommand.Path
    
    .PARAMETER ScriptParameters
        Hashtable of parameters to pass to the elevated script instance
    
    .PARAMETER ElevationAttempted
        Internal parameter to track if elevation has already been attempted (prevents infinite loops)
    
    .EXAMPLE
        # Basic usage at the start of a script
        Invoke-AdminElevation -ScriptPath $MyInvocation.MyCommand.Path
    
    .EXAMPLE
        # With parameters
        $params = @{ Force = $Force; Verbose = $VerbosePreference }
        Invoke-AdminElevation -ScriptPath $MyInvocation.MyCommand.Path -ScriptParameters $params
    
    .EXAMPLE
        # With elevation attempt tracking (internal use)
        Invoke-AdminElevation -ScriptPath $MyInvocation.MyCommand.Path -ElevationAttempted
    
    .NOTES
        - This function will exit the current script if elevation is needed
        - Should be called early in your script, before any admin-required operations
        - Automatically handles parameter preservation during elevation
        - Includes infinite loop prevention for environments where UAC is disabled
    #>
    
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ScriptPath,
        [hashtable]$ScriptParameters = @{},
        [switch]$ElevationAttempted
    )
    
    # Check if already running as administrator
    $IsAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
    if ($IsAdmin) {
        return
    }
    
    # Check if we've already attempted elevation to prevent infinite loops
    if ($ElevationAttempted) {
        Write-Status "Elevation attempt failed. UAC may be disabled or access was denied." "ERROR"
        Write-Status "Please run this script manually as an Administrator." "ERROR"
        Send-AnyKeyAndExit -Quit $true -ExitCode 1
    }
    
    Write-Status "This script needs to be run as an Administrative user." "WARNING"
    Write-Status "Attempting to restart with administrative privileges..." "INFO"
    
    try {
        # Build argument list starting with elevation flag
        $ArgumentList = "-NoProfile -ExecutionPolicy Bypass -File `"$ScriptPath`" -ElevationAttempted"
        
        # Add original parameters
        foreach ($param in $ScriptParameters.GetEnumerator()) {
            if ($param.Value -is [switch] -and $param.Value) {
                $ArgumentList += " -$($param.Key)"
            }
            elseif ($param.Value -and $param.Value -ne $false) {
                $ArgumentList += " -$($param.Key) `"$($param.Value)`""
            }
        }
        
        # Start the process with UAC prompt for elevation
        $Process = Start-Process -FilePath "powershell.exe" `
            -ArgumentList $ArgumentList `
            -Verb RunAs `
            -PassThru `
            -ErrorAction Stop
            
        # Wait for the elevated process to complete
        $Process.WaitForExit()
        exit $Process.ExitCode
    }
    catch {
        Write-Status "Failed to elevate privileges. Error: $($_.Exception.Message)" "ERROR"
        Write-Status "This could happen if:" "WARNING"
        Write-Status "- UAC is disabled" "WARNING"
        Write-Status "- You don't have administrator rights" "WARNING"
        Write-Status "- You cancelled the UAC prompt" "WARNING"
        Write-Host ""
        Write-Status "Please run this script manually as an Administrator." "ERROR"
        Send-AnyKeyAndExit -Quit $true -ExitCode 1
    }
}

# Export the function to make it available when the module is imported
Export-ModuleMember -Function Invoke-AdminElevation
