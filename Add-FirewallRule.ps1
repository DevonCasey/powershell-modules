# Windows Firewall Command Module (firewall-cmd style)
# Provides firewall-cmd like functionality for Windows

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
    #>    $IsAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    
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

# Export functions and aliases
Export-ModuleMember -Function Invoke-FirewallCmd, Test-AdminPrivileges -Alias "firewall-cmd"