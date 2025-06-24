# Windows Firewall Command Module (firewall-cmd style)
# Provides firewall-cmd like functionality for Windows

# Script parameters - allows script to be run directly with parameters
param(
    [Parameter()]
    [string]$DisplayName,
    
    [Parameter()]
    [ValidateSet('TCP', 'UDP')]
    [string]$Protocol,
    
    [Parameter()]
    [string]$LocalPort,
    
    [Parameter()]
    [ValidateSet('Inbound', 'Outbound')]
    [string]$Direction = 'Inbound',
    
    [Parameter()]
    [ValidateSet('Allow', 'Block')]
    [string]$Action = 'Allow',
    
    [Parameter()]
    [ValidateSet('Any', 'Domain', 'Private', 'Public')]
    [string]$Profile = 'Any',
    
    [Parameter()]
    [switch]$Interactive,
    
    [Parameter()]
    [switch]$Help
)

# Define predefined services
$script:PredefinedServices = @{
    'http'   = @{ Port = 80; Protocol = 'TCP'; Description = 'HTTP Web Server' }
    'https'  = @{ Port = 443; Protocol = 'TCP'; Description = 'HTTPS Web Server' }
    'ssh'    = @{ Port = 22; Protocol = 'TCP'; Description = 'SSH Remote Access' }
    'ftp'    = @{ Port = 21; Protocol = 'TCP'; Description = 'FTP Server' }
    'dns'    = @{ Port = 53; Protocol = 'UDP'; Description = 'DNS Server' }
    'smtp'   = @{ Port = 25; Protocol = 'TCP'; Description = 'SMTP Mail Server' }
    'telnet' = @{ Port = 23; Protocol = 'TCP'; Description = 'Telnet' }
    'rdp'    = @{ Port = 3389; Protocol = 'TCP'; Description = 'Remote Desktop' }
    'ntp'    = @{ Port = 123; Protocol = 'UDP'; Description = 'Network Time Protocol' }
    'snmp'   = @{ Port = 161; Protocol = 'UDP'; Description = 'SNMP' }
    'ping'   = @{ Port = -1; Protocol = 'ICMPv4'; Description = 'ICMP Ping' }
}

# Define firewall zones
$script:FirewallZones = @{
    'public'  = @{ Profile = 'Public'; Description = 'Public networks (untrusted)' }
    'private' = @{ Profile = 'Private'; Description = 'Private networks (home/office)' }
    'domain'  = @{ Profile = 'Domain'; Description = 'Domain networks (enterprise)' }
    'work'    = @{ Profile = 'Private'; Description = 'Work networks' }
    'home'    = @{ Profile = 'Private'; Description = 'Home networks' }
}

function Test-AdminPrivileges {
    <#
    .SYNOPSIS
        Tests if the current session has administrator privileges.
    #>
    $IsAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    
    if (-not $IsAdmin) {
        Write-Error "This operation requires administrator privileges."
        return $false
    }
    return $true
}

function Invoke-FirewallCmd {
    <#
    .SYNOPSIS
        Windows equivalent of firewall-cmd for managing Windows Firewall.
    
    .DESCRIPTION
        Provides firewall-cmd like functionality for Windows Firewall management,
        including zone management, service definitions, and rule operations.
    
    .PARAMETER Zone
        Specifies the firewall zone (public, private, domain, work, home).
    
    .PARAMETER AddService
        Adds a predefined service to the firewall.
    
    .PARAMETER RemoveService
        Removes a predefined service from the firewall.
    
    .PARAMETER AddPort
        Adds a port/protocol combination (e.g., "80/tcp", "53/udp").
    
    .PARAMETER RemovePort
        Removes a port/protocol combination.
    
    .PARAMETER AddSource
        Adds a source IP or subnet to allow.
    
    .PARAMETER RemoveSource
        Removes a source IP or subnet.
    
    .PARAMETER ListAll
        Lists all firewall rules and configuration.
    
    .PARAMETER ListServices
        Lists all available predefined services.
    
    .PARAMETER ListZones
        Lists all available zones.
    
    .PARAMETER ListPorts
        Lists all open ports for the specified zone.
    
    .PARAMETER State
        Shows or sets the firewall state (on/off).
    
    .PARAMETER Reload
        Reloads the firewall configuration.
    
    .PARAMETER Permanent
        Makes changes permanent (persistent across reboots).
    
    .PARAMETER Runtime
        Makes changes to runtime only (temporary).
    
    .EXAMPLE
        Invoke-FirewallCmd -ListZones
        Lists all available firewall zones.
    
    .EXAMPLE
        Invoke-FirewallCmd -Zone public -AddService http
        Adds HTTP service to the public zone.
    
    .EXAMPLE
        Invoke-FirewallCmd -Zone private -AddPort "8080/tcp" -Permanent
        Permanently adds TCP port 8080 to the private zone.
    
    .EXAMPLE
        Invoke-FirewallCmd -Zone public -AddSource "192.168.1.0/24"
        Allows traffic from the 192.168.1.0/24 subnet in public zone.
    #>
    [CmdletBinding(DefaultParameterSetName = 'ListAll')]
    param (
        [Parameter()]
        [ValidateSet('public', 'private', 'domain', 'work', 'home')]
        [string]$Zone = 'public',
        
        [Parameter(ParameterSetName = 'AddService')]
        [string]$AddService,
        
        [Parameter(ParameterSetName = 'RemoveService')]
        [string]$RemoveService,
        
        [Parameter(ParameterSetName = 'AddPort')]
        [string]$AddPort,
        
        [Parameter(ParameterSetName = 'RemovePort')]
        [string]$RemovePort,
        
        [Parameter(ParameterSetName = 'AddSource')]
        [string]$AddSource,
        
        [Parameter(ParameterSetName = 'RemoveSource')]
        [string]$RemoveSource,
        
        [Parameter(ParameterSetName = 'ListAll')]
        [switch]$ListAll,
        
        [Parameter(ParameterSetName = 'ListServices')]
        [switch]$ListServices,
        
        [Parameter(ParameterSetName = 'ListZones')]
        [switch]$ListZones,
        
        [Parameter(ParameterSetName = 'ListPorts')]
        [switch]$ListPorts,
        
        [Parameter(ParameterSetName = 'State')]
        [ValidateSet('on', 'off', 'status')]
        [string]$State,
        
        [Parameter(ParameterSetName = 'Reload')]
        [switch]$Reload,
        
        [Parameter()]
        [switch]$Permanent,
        
        [Parameter()]
        [switch]$Runtime
    )
    # Default to runtime if neither permanent nor runtime specified
    if (-not $Permanent -and -not $Runtime) {
        $Runtime = $true
    }
    
    switch ($PSCmdlet.ParameterSetName) {
        'AddService' {
            if (-not (Test-AdminPrivileges)) { return }
            Add-FirewallService -Service $AddService -Zone $Zone -Permanent:$Permanent
        }
        
        'RemoveService' {
            if (-not (Test-AdminPrivileges)) { return }
            Remove-FirewallService -Service $RemoveService -Zone $Zone -Permanent:$Permanent
        }
        
        'AddPort' {
            if (-not (Test-AdminPrivileges)) { return }
            Add-FirewallPort -PortProtocol $AddPort -Zone $Zone -Permanent:$Permanent
        }
        
        'RemovePort' {
            if (-not (Test-AdminPrivileges)) { return }
            Remove-FirewallPort -PortProtocol $RemovePort -Zone $Zone -Permanent:$Permanent
        }
        
        'AddSource' {
            if (-not (Test-AdminPrivileges)) { return }
            Add-FirewallSource -Source $AddSource -Zone $Zone -Permanent:$Permanent
        }
        
        'RemoveSource' {
            if (-not (Test-AdminPrivileges)) { return }
            Remove-FirewallSource -Source $RemoveSource -Zone $Zone -Permanent:$Permanent
        }
        
        'ListAll' {
            Show-FirewallStatus -Zone $Zone
        }
        
        'ListServices' {
            Show-PredefinedServices
        }
        
        'ListZones' {
            Show-FirewallZones
        }
        
        'ListPorts' {
            Show-FirewallPorts -Zone $Zone
        }
        
        'State' {
            if ($State -eq 'status') {
                Show-FirewallState
            }
            else {
                if (-not (Test-AdminPrivileges)) { return }
                Set-FirewallState -State $State
            }
        }
        
        'Reload' {
            if (-not (Test-AdminPrivileges)) { return }
            Restart-Service -Name "MpsSvc" -Force
            Write-Output "Firewall configuration reloaded."
        }
    }
}

function Add-FirewallService {
    param(
        [string]$Service,
        [string]$Zone,
        [bool]$Permanent
    )
    
    if (-not $script:PredefinedServices.ContainsKey($Service)) {
        Write-Error "Unknown service: $Service. Use 'Invoke-FirewallCmd -ListServices' to see available services."
        return    
    }
    
    $ServiceDef = $script:PredefinedServices[$Service]
    $FirewallProfile = $script:FirewallZones[$Zone].Profile
    
    $RuleName = "firewall-cmd-$Zone-$Service"
    
    # Check if rule already exists
    $ExistingRule = Get-NetFirewallRule -DisplayName $RuleName -ErrorAction SilentlyContinue
    if ($ExistingRule) {
        Write-Warning "Service '$Service' is already enabled in zone '$Zone'."
        return
    }
    
    try {
        if ($ServiceDef.Protocol -eq 'ICMPv4') {
            New-NetFirewallRule -DisplayName $RuleName -Direction Inbound -Protocol $ServiceDef.Protocol -Action Allow -Profile $FirewallProfile -Enabled True | Out-Null
        }
        else {
            New-NetFirewallRule -DisplayName $RuleName -Direction Inbound -Protocol $ServiceDef.Protocol -LocalPort $ServiceDef.Port -Action Allow -Profile $FirewallProfile -Enabled True | Out-Null
        }
        
        Write-Output "success: Added service '$Service' to zone '$Zone'$(if($Permanent){' (permanent)'}else{' (runtime only)'})."
    }
    catch {
        Write-Error "Failed to add service '$Service': $_"
    }
}

function Remove-FirewallService {
    param(
        [string]$Service,
        [string]$Zone,
        [bool]$Permanent
    )
    
    $RuleName = "firewall-cmd-$Zone-$Service"
    
    try {
        $Rule = Get-NetFirewallRule -DisplayName $RuleName -ErrorAction SilentlyContinue
        if ($Rule) {
            Remove-NetFirewallRule -DisplayName $RuleName
            Write-Output "success: Removed service '$Service' from zone '$Zone'$(if($Permanent){' (permanent)'}else{' (runtime only)'})."
        }
        else {
            Write-Warning "Service '$Service' is not enabled in zone '$Zone'."
        }
    }
    catch {
        Write-Error "Failed to remove service '$Service': $_"
    }
}

function Add-FirewallPort {
    param(
        [string]$PortProtocol,
        [string]$Zone,
        [bool]$Permanent
    )
    if ($PortProtocol -notmatch '^(\d+)/(tcp|udp)$') {
        Write-Error "Invalid port/protocol format. Use format like '80/tcp' or '53/udp'."
        return
    }
    
    $Port = $Matches[1]
    $Protocol = $Matches[2].ToUpper()
    $FirewallProfile = $script:FirewallZones[$Zone].Profile
    
    $RuleName = "firewall-cmd-$Zone-$Port-$Protocol"
    $ExistingRule = Get-NetFirewallRule -DisplayName $RuleName -ErrorAction SilentlyContinue
    if ($ExistingRule) {
        Write-Warning "Port '$PortProtocol' is already open in zone '$Zone'."
        return
    }
    
    try {
        New-NetFirewallRule -DisplayName $RuleName -Direction Inbound -Protocol $Protocol -LocalPort $Port -Action Allow -Profile $FirewallProfile -Enabled True | Out-Null
        Write-Output "success: Added port '$PortProtocol' to zone '$Zone'$(if($Permanent){' (permanent)'}else{' (runtime only)'})."
    }
    catch {
        Write-Error "Failed to add port '$PortProtocol': $_"
    }
}

function Remove-FirewallPort {
    param(
        [string]$PortProtocol,
        [string]$Zone,
        [bool]$Permanent
    )
    
    if ($PortProtocol -notmatch '^(\d+)/(tcp|udp)$') {
        Write-Error "Invalid port/protocol format. Use format like '80/tcp' or '53/udp'."
        return
    }
    
    $Port = $Matches[1]
    $Protocol = $Matches[2].ToUpper()
    $RuleName = "firewall-cmd-$Zone-$Port-$Protocol"
    
    try {
        $Rule = Get-NetFirewallRule -DisplayName $RuleName -ErrorAction SilentlyContinue
        if ($Rule) {
            Remove-NetFirewallRule -DisplayName $RuleName
            Write-Output "success: Removed port '$PortProtocol' from zone '$Zone'$(if($Permanent){' (permanent)'}else{' (runtime only)'})."
        }
        else {
            Write-Warning "Port '$PortProtocol' is not open in zone '$Zone'."
        }
    }
    catch {
        Write-Error "Failed to remove port '$PortProtocol': $_"
    }
}

function Add-FirewallSource {
    param(
        [string]$Source,
        [string]$Zone,
        [bool]$Permanent
    )
    $FirewallProfile = $script:FirewallZones[$Zone].Profile
    $RuleName = "firewall-cmd-$Zone-source-$($Source -replace '[./]', '-')"
    
    # Check if rule already exists
    $ExistingRule = Get-NetFirewa   llRule -DisplayName $RuleName -ErrorAction SilentlyContinue
    if ($ExistingRule) {
        Write-Warning "Source '$Source' is already allowed in zone '$Zone'."
        return
    }
    
    try {
        New-NetFirewallRule -DisplayName $RuleName -Direction Inbound -RemoteAddress $Source -Action Allow -Profile $FirewallProfile -Enabled True | Out-Null
        Write-Output "SUCCESS: Added source '$Source' to zone '$Zone'$(if($Permanent){' (permanent)'}else{' (runtime only)'})."
    }
    catch {
        Write-Error "Failed to add source '$Source': $_"
    }
}

function Remove-FirewallSource {
    param(
        [string]$Source,
        [string]$Zone,
        [bool]$Permanent
    )
    $RuleName = "firewall-cmd-$Zone-source-$($Source -replace '[./]', '-')"
    
    try {
        $Rule = Get-NetFirewallRule -DisplayName $RuleName -ErrorAction SilentlyContinue
        if ($Rule) {
            Remove-NetFirewallRule -DisplayName $RuleName
            Write-Output "success: Removed source '$Source' from zone '$Zone'$(if($Permanent){' (permanent)'}else{' (runtime only)'})."
        }
        else {
            Write-Warning "Source '$Source' is not allowed in zone '$Zone'."
        }
    }
    catch {
        Write-Error "Failed to remove source '$Source': $_"
    }
}

function Show-FirewallStatus {
    param([string]$Zone)
    
    $FirewallProfile = $script:FirewallZones[$Zone].Profile
    Write-Output "`n=== Firewall Status for Zone: $Zone ($FirewallProfile) ==="
    # Show firewall state
    $FirewallProfileInfo = Get-NetFirewallProfile -Name $FirewallProfile
    Write-Output "Firewall State: $($FirewallProfileInfo.Enabled)"
    Write-Output "Default Action: $($FirewallProfileInfo.DefaultInboundAction)"
    
    # Show active rules for this zone
    $Rules = Get-NetFirewallRule | Where-Object { $_.Profile -match $FirewallProfile -and $_.DisplayName -like "firewall-cmd-$Zone-*" }
    Write-Output "`nActive Rules:"
    if ($Rules) {
        foreach ($Rule in $Rules) {
            $PortFilter = $Rule | Get-NetFirewallPortFilter -ErrorAction SilentlyContinue
            $AddressFilter = $Rule | Get-NetFirewallAddressFilter -ErrorAction SilentlyContinue
            
            $RuleInfo = "  - $($Rule.DisplayName) [$($Rule.Direction)] [$($Rule.Action)]"
            if ($PortFilter -and $PortFilter.LocalPort -ne 'Any') {
                $RuleInfo += " Port: $($PortFilter.LocalPort)/$($PortFilter.Protocol)"
            }
            if ($AddressFilter -and $AddressFilter.RemoteAddress -ne 'Any') {
                $RuleInfo += " Source: $($AddressFilter.RemoteAddress)"
            }
            Write-Output $RuleInfo
        }
    }
    else {
        Write-Output "  No custom rules found for zone '$Zone'."
    }
}

function Show-PredefinedServices {
    Write-Output "`n=== Available Predefined Services ==="
    foreach ($service in $script:PredefinedServices.GetEnumerator() | Sort-Object Name) {
        $def = $service.Value
        if ($def.Protocol -eq 'ICMPv4') {
            Write-Output "  $($service.Name.PadRight(10)) - $($def.Protocol.PadRight(8)) - $($def.Description)"
        }
        else {
            Write-Output "  $($service.Name.PadRight(10)) - $($def.Port.ToString().PadRight(5))/$($def.Protocol.PadRight(3)) - $($def.Description)"
        }
    }
}

function Show-FirewallZones {
    Write-Output "`n=== Available Firewall Zones ==="
    foreach ($zone in $script:FirewallZones.GetEnumerator() | Sort-Object Name) {
        Write-Output "  $($zone.Name.PadRight(10)) - $($zone.Value.Profile.PadRight(8)) - $($zone.Value.Description)"
    }
}

function Show-FirewallPorts {
    param([string]$Zone)
    
    Write-Output "`n=== Open Ports for Zone: $Zone ==="
    $rules = Get-NetFirewallRule | Where-Object { $_.DisplayName -like "firewall-cmd-$Zone-*" -and $_.DisplayName -notlike "*source*" }
    
    if ($rules) {
        foreach ($rule in $rules) {
            $portFilter = $rule | Get-NetFirewallPortFilter -ErrorAction SilentlyContinue
            if ($portFilter -and $portFilter.LocalPort -ne 'Any') {
                Write-Output "  $($portFilter.LocalPort)/$($portFilter.Protocol.ToLower())"
            }
        }
    }
    else {
        Write-Output "  No ports are explicitly open for zone '$Zone'."
    }
}

function Show-FirewallState {
    Write-Output "`n=== Windows Firewall State ==="
    $profiles = Get-NetFirewallProfile
    foreach ($profile in $profiles) {
        Write-Output "$($profile.Name): $($profile.Enabled)"
    }
}

function Set-FirewallState {
    param([string]$State)
    $EnableState = if ($State -eq 'on') { $true } else { $false }
    
    try {
        Set-NetFirewallProfile -All -Enabled $EnableState
        Write-Output "success: Firewall state changed to '$State'."
    }
    catch {
        Write-Error "Failed to change firewall state: $_"
    }
}

# Create aliases for common firewall-cmd patterns
New-Alias -Name "firewall-cmd" -Value "Invoke-FirewallCmd" -Force

function Add-FirewallRule {
    <#
    .SYNOPSIS
        Creates a new Windows Firewall rule with the specified parameters.
    
    .DESCRIPTION
        Creates a new inbound firewall rule with the specified display name, protocol, and ports.
        This function provides a simple interface for creating firewall rules without needing
        to use the full firewall-cmd syntax. If parameters are not provided, the function will
        prompt interactively for required values.
    
    .PARAMETER DisplayName
        The name of the firewall rule to create.
    
    .PARAMETER Protocol
        The protocol for the rule (TCP or UDP).
    
    .PARAMETER LocalPort
        The local port(s) to open. Can be a single port or range (e.g., "80" or "7751-7753").
    
    .PARAMETER Direction
        The direction of the rule (Inbound or Outbound). Defaults to Inbound.
    
    .PARAMETER Action
        The action to take for matching traffic (Allow or Block). Defaults to Allow.
    
    .PARAMETER Profile
        The firewall profile(s) to apply the rule to. Defaults to Any.
    
    .PARAMETER Interactive
        Forces interactive mode even when parameters are provided.
    
    .EXAMPLE
        Add-FirewallRule -DisplayName "My App (TCP-In)" -Protocol TCP -LocalPort "8080"
        Creates an inbound TCP rule for port 8080.
    
    .EXAMPLE
        Add-FirewallRule -DisplayName "My Service (TCP-In)" -Protocol TCP -LocalPort "7751-7753"
        Creates an inbound TCP rule for ports 7751 through 7753.
    
    .EXAMPLE
        Add-FirewallRule
        Runs in interactive mode, prompting for all required parameters.
    
    .EXAMPLE
        Add-FirewallRule -Interactive
        Forces interactive mode even if some parameters are provided.
    #>
    [CmdletBinding()]
    param (
        [Parameter()]
        [string]$DisplayName,
        
        [Parameter()]
        [ValidateSet('TCP', 'UDP')]
        [string]$Protocol,
        
        [Parameter()]
        [string]$LocalPort,
        
        [Parameter()]
        [ValidateSet('Inbound', 'Outbound')]
        [string]$Direction = 'Inbound',
        
        [Parameter()]
        [ValidateSet('Allow', 'Block')]
        [string]$Action = 'Allow',
        
        [Parameter()]
        [ValidateSet('Any', 'Domain', 'Private', 'Public')]
        [string]$Profile = 'Any',
        
        [Parameter()]
        [switch]$Interactive    )
    
    # Check for admin privileges first
    if (-not (Test-AdminPrivileges)) { 
        return $false
    }
    
    # Interactive mode logic - prompt for missing required parameters
    if ($Interactive -or [string]::IsNullOrEmpty($DisplayName) -or [string]::IsNullOrEmpty($Protocol) -or [string]::IsNullOrEmpty($LocalPort)) {
        Write-Host "`n=== Interactive Firewall Rule Creation ===" -ForegroundColor Cyan
        Write-Host "Press Ctrl+C at any time to cancel.`n" -ForegroundColor Yellow
        
        # Display Name
        if ($Interactive -or [string]::IsNullOrEmpty($DisplayName)) {
            do {
                $DisplayName = Read-Host -Prompt "Enter display name for the firewall rule"
                if ([string]::IsNullOrEmpty($DisplayName)) {
                    Write-Host "Display name is required." -ForegroundColor Red
                }
            } while ([string]::IsNullOrEmpty($DisplayName))
        }
        
        # Protocol
        if ($Interactive -or [string]::IsNullOrEmpty($Protocol)) {
            do {
                Write-Host "`nAvailable protocols:"
                Write-Host "  1. TCP"
                Write-Host "  2. UDP"
                $protocolChoice = Read-Host -Prompt "Select protocol (1-2 or TCP/UDP)"
                
                switch ($protocolChoice.ToUpper()) {
                    "1" { $Protocol = "TCP"; break }
                    "2" { $Protocol = "UDP"; break }
                    "TCP" { $Protocol = "TCP"; break }
                    "UDP" { $Protocol = "UDP"; break }
                    default { 
                        Write-Host "Invalid selection. Please choose 1, 2, TCP, or UDP." -ForegroundColor Red
                        $Protocol = $null
                    }
                }
            } while ([string]::IsNullOrEmpty($Protocol))
        }
        
        # Local Port
        if ($Interactive -or [string]::IsNullOrEmpty($LocalPort)) {
            do {
                Write-Host "`nExamples: 80, 8080, 7751-7753, 443"
                $LocalPort = Read-Host -Prompt "Enter local port(s)"
                if ([string]::IsNullOrEmpty($LocalPort)) {
                    Write-Host "Local port is required." -ForegroundColor Red
                } elseif ($LocalPort -notmatch '^\d+(-\d+)?$' -and $LocalPort -notmatch '^\d+(,\d+)*$') {
                    Write-Host "Invalid port format. Use single port (80), range (7751-7753), or comma-separated (80,443)." -ForegroundColor Red
                    $LocalPort = $null
                }
            } while ([string]::IsNullOrEmpty($LocalPort))
        }
        
        # Direction (optional - show current default)
        if ($Interactive) {
            Write-Host "`nAvailable directions:"
            Write-Host "  1. Inbound (default)"
            Write-Host "  2. Outbound"
            $directionChoice = Read-Host -Prompt "Select direction (1-2, Enter for default: $Direction)"
            
            if (-not [string]::IsNullOrEmpty($directionChoice)) {
                switch ($directionChoice) {
                    "1" { $Direction = "Inbound" }
                    "2" { $Direction = "Outbound" }
                    default { 
                        Write-Host "Invalid selection, using default: $Direction" -ForegroundColor Yellow
                    }
                }
            }
        }
        
        # Action (optional - show current default)
        if ($Interactive) {
            Write-Host "`nAvailable actions:"
            Write-Host "  1. Allow (default)"
            Write-Host "  2. Block"
            $actionChoice = Read-Host -Prompt "Select action (1-2, Enter for default: $Action)"
            
            if (-not [string]::IsNullOrEmpty($actionChoice)) {
                switch ($actionChoice) {
                    "1" { $Action = "Allow" }
                    "2" { $Action = "Block" }
                    default { 
                        Write-Host "Invalid selection, using default: $Action" -ForegroundColor Yellow
                    }
                }
            }
        }
        
        # Profile (optional - show current default)
        if ($Interactive) {
            Write-Host "`nAvailable profiles:"
            Write-Host "  1. Any (default)"
            Write-Host "  2. Domain"
            Write-Host "  3. Private"
            Write-Host "  4. Public"
            $profileChoice = Read-Host -Prompt "Select profile (1-4, Enter for default: $Profile)"
            
            if (-not [string]::IsNullOrEmpty($profileChoice)) {
                switch ($profileChoice) {
                    "1" { $Profile = "Any" }
                    "2" { $Profile = "Domain" }
                    "3" { $Profile = "Private" }
                    "4" { $Profile = "Public" }
                    default { 
                        Write-Host "Invalid selection, using default: $Profile" -ForegroundColor Yellow
                    }
                }
            }
        }
        
        # Confirmation
        Write-Host "`n=== Firewall Rule Summary ===" -ForegroundColor Cyan
        Write-Host "Display Name: $DisplayName"
        Write-Host "Protocol:     $Protocol"
        Write-Host "Local Port:   $LocalPort"
        Write-Host "Direction:    $Direction"
        Write-Host "Action:       $Action"
        Write-Host "Profile:      $Profile"
        
        $confirm = Read-Host "`nCreate this firewall rule? (y/N)"
        if ($confirm -notmatch '^[Yy]') {
            Write-Host "Operation cancelled." -ForegroundColor Yellow
            return $false
        }
    }
    
    # Validate required parameters are now populated
    if ([string]::IsNullOrEmpty($DisplayName) -or [string]::IsNullOrEmpty($Protocol) -or [string]::IsNullOrEmpty($LocalPort)) {
        Write-Error "Missing required parameters: DisplayName, Protocol, and LocalPort are mandatory."
        return $false
    }
    
    # Check if rule already exists
    $ExistingRule = Get-NetFirewallRule -DisplayName $DisplayName -ErrorAction SilentlyContinue
    if ($ExistingRule) {
        Write-Warning "Firewall rule '$DisplayName' already exists."
        return $true
    }
    
    try {
        New-NetFirewallRule -DisplayName $DisplayName -Direction $Direction -Protocol $Protocol -LocalPort $LocalPort -Action $Action -Profile $Profile -Enabled True | Out-Null
        Write-Output "Successfully created firewall rule: $DisplayName"
        return $true
    }
    catch {
        Write-Error "Failed to create firewall rule '$DisplayName': $_"
        return $false
    }
}

# Alias this as firewall-cmd because linux is good.
# Export-ModuleMember -Function Invoke-FirewallCmd, Test-AdminPrivileges, Add-FirewallRule -Alias "firewall-cmd"

# Main execution - runs when script is executed directly (not dot-sourced)
if ($MyInvocation.InvocationName -ne '.' -and $MyInvocation.Line -notmatch '^\s*\.' ) {
    # Show help if requested
    if ($Help) {
        Get-Help Add-FirewallRule -Detailed
        exit
    }
    
    Write-Host "Windows Firewall Rule Creator" -ForegroundColor Green
    Write-Host "============================`n" -ForegroundColor Green
    
    # Check if any parameters were provided
    $hasParams = $PSBoundParameters.Keys | Where-Object { $_ -notin @('Help', 'Interactive') } | Measure-Object | Select-Object -ExpandProperty Count
    
    if ($hasParams -gt 0 -or $Interactive) {
        # Use provided parameters (function will handle prompting for missing ones)
        $params = @{}
        if ($DisplayName) { $params.DisplayName = $DisplayName }
        if ($Protocol) { $params.Protocol = $Protocol }
        if ($LocalPort) { $params.LocalPort = $LocalPort }
        if ($Direction) { $params.Direction = $Direction }
        if ($Action) { $params.Action = $Action }
        if ($Profile) { $params.Profile = $Profile }
        if ($Interactive) { $params.Interactive = $true }
        
        $result = Add-FirewallRule @params
    } else {
        # No parameters provided, run in interactive mode
        $result = Add-FirewallRule -Interactive
    }
    
    if ($result) {
        Write-Host "`nFirewall rule created successfully!" -ForegroundColor Green
    } else {
        Write-Host "`nFirewall rule creation failed or was cancelled." -ForegroundColor Red
        exit 1
    }
}