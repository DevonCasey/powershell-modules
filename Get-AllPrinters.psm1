# Get-AllPrinters.psm1
# WCL Public PC Scripts - Get-AllPrinters Module
# This module provides printer discovery functionality

# Import required module for Write-Status
Import-Module (Join-Path $PSScriptRoot "Write-Status.psm1") -Force

function Get-AllPrinters {
    <#
    .SYNOPSIS
        Gets all printer names from a specified print server.
    
    .DESCRIPTION
        This function retrieves a list of all printer names from a specified print server
        using the Get-Printer cmdlet. It filters to only return online printers, excluding
        those that are offline, in error state, or in power save mode.
    
    .PARAMETER PrintServerName
        The name of the print server. If not specified, the local computer is used.
    
    .EXAMPLE
        Get-AllPrinters
        
        Returns all online printers on the local machine.
    
    .EXAMPLE
        Get-AllPrinters -PrintServerName "PrintServer01"
        
        Returns all online printers on PrintServer01.
    
    .EXAMPLE
        "PrintServer01", "PrintServer02" | Get-AllPrinters
        
        Returns all online printers from multiple print servers via pipeline.
    
    .NOTES
        - Only returns printers that are online and available
        - Excludes printers in Offline, Error, or PowerSave states
        - Returns printer names sorted alphabetically
        - Requires appropriate permissions to query the target print server
    #>
    
    [CmdletBinding()]
    param (
        [Parameter(ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [string]$PrintServerName = $env:COMPUTERNAME
    )
    
    process {
        try {
            Write-Status "Retrieving printers from $PrintServerName" "INFO"
            
            $PrinterList = Get-Printer -ComputerName $PrintServerName -ErrorAction Stop
            if (-not $PrinterList) {
                Write-Status "No printers found on $PrintServerName." "INFO"
                return
            }
            
            # Filter to only get online printers - exclude offline, error, and power save states
            $OnlinePrinters = $PrinterList | Where-Object { 
                $_.PrinterStatus -ne "Offline" -and 
                $_.PrinterStatus -ne "Error" -and
                $_.PrinterStatus -ne "PowerSave"
            }
            
            if (-not $OnlinePrinters) {
                Write-Status "No online printers found on $PrintServerName." "INFO"
                return
            }
            
            $PrinterNameList = $OnlinePrinters | Select-Object -ExpandProperty Name | Sort-Object
            if (-not $PrinterNameList) {
                Write-Status "No online printer names found on $PrintServerName." "INFO"
                return
            }
            
            Write-Status "Found $($PrinterNameList.Count) online printer(s) on $PrintServerName" "SUCCESS"
            return $PrinterNameList
        }
        catch {
            Write-Status "Failed to retrieve printers from $PrintServerName. Error: $_" "ERROR"
            return
        }
    }
}

# Export the function to make it available when the module is imported
Export-ModuleMember -Function Get-AllPrinters
