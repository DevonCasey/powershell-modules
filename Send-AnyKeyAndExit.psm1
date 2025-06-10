# Send-AnyKeyAndExit.psm1
# WCL Public PC Scripts - Send-AnyKeyAndExit Module
# This module provides consistent user interaction and script termination

function Send-AnyKeyAndExit {
    <#
    .SYNOPSIS
        Displays a message and waits for user input before exiting the script.
    
    .DESCRIPTION
        This function provides a consistent way to pause and exit scripts with user interaction.
        It can optionally stop any active transcription before exiting.
    
    .PARAMETER Quit
        When set to $true, displays "Press any key to quit" and exits the script.
        When set to $false, simply returns without exiting.
    
    .PARAMETER ExitCode
        The exit code to use when exiting. Defaults to 0 (success).
    
    .EXAMPLE
        Send-AnyKeyAndExit -Quit $true
        Displays the quit message and exits with code 0.
    
    .EXAMPLE
        Send-AnyKeyAndExit -Quit $true -ExitCode 1
        Displays the quit message and exits with code 1 (error).
    
    .EXAMPLE
        Send-AnyKeyAndExit -Quit $false
        Returns without doing anything (useful for conditional exits).
    
    .NOTES
        - Automatically handles stopping transcripts if they are active
        - Use ExitCode 0 for successful completion
        - Use ExitCode 1 for errors or failures
    #>
    
    [CmdletBinding()]
    param(
        [bool]$Quit = $false,
        [int]$ExitCode = 0
    )
    
    if ($Quit -eq $true) {
        Write-Host "Press any key to quit."
        [void][System.Console]::ReadKey($true)
        if ($Host.Transcribing) {
            Stop-Transcript | Out-Null
        }
        exit $ExitCode
    }
    else {
        return
    }
}

# Export the function to make it available when the module is imported
Export-ModuleMember -Function Send-AnyKeyAndExit
