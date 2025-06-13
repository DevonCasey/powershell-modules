function Add-FirewallRule {
    <#
    .SYNOPSIS
        Adds a custom Windows Firewall rule.
    
    .DESCRIPTION
        This function creates a Windows Firewall rule for any specified port and protocol.
      .PARAMETER Direction
        Specifies the direction of the rule. Must be either "Inbound" or "Outbound".
    
    .PARAMETER Protocol
        Specifies the protocol for the rule. Must be either "TCP" or "UDP".
    
    .PARAMETER Port
        Specifies the port number.
    
    .PARAMETER AppName
        Specifies the application name for the firewall rule (e.g., "HTTP", "iPerf3").        The full rule name will be constructed as "AppName (Protocol-Direction)".
    
    .PARAMETER Description
        Specifies the description for the firewall rule.
      .EXAMPLE
        Add-FirewallRule -Direction "Inbound" -Protocol "TCP" -Port 80 -AppName "HTTP"
        
        Creates an inbound TCP rule for port 80 with the name "HTTP (TCP-Inbound)".
    
    .EXAMPLE
        Add-FirewallRule -Direction "Outbound" -Protocol "UDP" -Port 53 -AppName "DNS"
          Creates an outbound UDP rule for port 53 with the name "DNS (UDP-Outbound)".
    
    .NOTES
        Requires administrative privileges to add firewall rules.
    #>    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [ValidateSet("Inbound", "Outbound")]
        [string]$Direction,
        
        [Parameter(Mandatory)]
        [ValidateSet("TCP", "UDP")]        
        [string]$Protocol,
        
        [Parameter(Mandatory)]
        [int]$Port,
        
        [Parameter(Mandatory)]
        [string]$AppName,
        
        [Parameter()]
        [string]$Description
    )
    
    begin {
        # Check for administrator privileges
        $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        
        if (-not $isAdmin) {
            Write-Error "This function requires administrator privileges to create firewall rules."
            return
        }    
    }
    
    process {
        try {
            # Build the full rule name from the application name
            $FullRuleName = "$AppName ($Protocol-$Direction)"
            
            # Set default description if not provided
            if (-not $Description) {
                $Description = "Allow $Direction $Protocol traffic on port $Port for $AppName"
            }
            
            # Check if the rule already exists
            $existingRule = Get-NetFirewallRule -DisplayName $FullRuleName -ErrorAction SilentlyContinue
            
            if ($existingRule) {
                Write-Warning "A firewall rule with the name '$FullRuleName' already exists. Skipping creation."
                return $existingRule
            }
            
            # Create the firewall rule
            $FirewallParams = @{
                DisplayName = $FullRuleName
                Description = $Description
                Direction   = $Direction
                Protocol    = $Protocol
                LocalPort   = $Port
                Action      = "Allow"
                Enabled     = "True"
            }
            
            $newRule = New-NetFirewallRule @FirewallParams
            
            Write-Output "Firewall rule '$FullRuleName' created successfully for $Protocol port $Port ($Direction)."
            return $newRule
        }
        catch {
            Write-Error "Failed to create firewall rule: $_"
        }
    }
}

# Export the function
Export-ModuleMember -Function Add-FirewallRule