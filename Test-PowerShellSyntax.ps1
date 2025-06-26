<#
.SYNOPSIS
    Test-PowerShellSyntax - Advanced PowerShell script validation tool

.DESCRIPTION
    A comprehensive PowerShell script validation tool that checks syntax, function dependencies,
    and common formatting issues. Designed to work with modular PowerShell environments.

.PARAMETER ScriptPath
    Path to the PowerShell script file to validate

.PARAMETER ModulePath
    Optional additional path to search for PowerShell modules (.psm1 files).
    The script automatically detects Import-Module statements and searches standard locations.

.PARAMETER Quick
    Perform only syntax validation (fastest check)

.PARAMETER Detailed
    Show detailed information about functions and dependencies

.PARAMETER ShowAllModules
    Show all modules including common system modules (normally hidden)

.EXAMPLE
    Test-PowerShellSyntax -ScriptPath "C:\Scripts\MyScript.ps1"
    
.EXAMPLE
    Test-PowerShellSyntax -ScriptPath "C:\Scripts\MyScript.ps1" -ModulePath "C:\Modules" -Detailed
    
.EXAMPLE
    Test-PowerShellSyntax -ScriptPath "C:\Scripts\MyScript.ps1" -Detailed -ShowAllModules
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateScript({Test-Path $_ -PathType Leaf})]
    [string]$ScriptPath,
    
    [Parameter(Mandatory = $false)]
    [string]$ModulePath,
    
    [Parameter(Mandatory = $false)]
    [switch]$Quick,
    
    [Parameter(Mandatory = $false)]
    [switch]$Detailed,
    
    [Parameter(Mandatory = $false)]
    [switch]$ShowAllModules
)

function Write-ValidationResult {
    param(
        [string]$Message,
        [ValidateSet("SUCCESS", "ERROR", "WARNING", "INFO")]
        [string]$Type,
        [int]$Indent = 0
    )
    
    $IndentStr = "  " * $Indent
    $Icon = switch ($Type) {
        "SUCCESS" { "[+]"; break }
        "ERROR"   { "[X]"; break }
        "WARNING" { "[!]"; break }
        "INFO"    { "[i]"; break }
    }
    
    $Color = switch ($Type) {
        "SUCCESS" { "Green"; break }
        "ERROR"   { "Red"; break }
        "WARNING" { "Yellow"; break }
        "INFO"    { "Cyan"; break }
    }
    
    Write-Host "$IndentStr$Icon $Message" -ForegroundColor $Color
}

function Test-PowerShellSyntax {
    param([string]$FilePath)
    
    Write-ValidationResult "Validating PowerShell syntax..." "INFO"
    
    try {
        $content = Get-Content $FilePath -Raw
        $errors = @()
        $null = [System.Management.Automation.Language.Parser]::ParseInput($content, [ref]$null, [ref]$errors)
        
        if ($errors.Count -eq 0) {
            Write-ValidationResult "Syntax validation passed" "SUCCESS" 1
            return @{ Valid = $true; Errors = @() }
        }
        else {
            Write-ValidationResult "Syntax errors found ($($errors.Count))" "ERROR" 1
            foreach ($error in $errors) {
                Write-ValidationResult "Line $($error.Extent.StartLineNumber): $($error.Message)" "ERROR" 2
            }
            return @{ Valid = $false; Errors = $errors }
        }
    }
    catch {
        Write-ValidationResult "Failed to parse script: $($_.Exception.Message)" "ERROR" 1
        return @{ Valid = $false; Errors = @($_.Exception.Message) }
    }
}

function Get-ScriptFunctionDefinitions {
    param([string]$FilePath)
    
    $Content = Get-Content $FilePath -Raw
    $Functions = @()
    
    # Find function definitions using regex
    $FunctionPattern = '(?m)^[ \t]*function\s+([a-zA-Z][a-zA-Z0-9_-]*)\s*(?:\([^)]*\))?\s*\{'
    $FunctionMatches = [regex]::Matches($Content, $FunctionPattern)
    
    foreach ($Match in $FunctionMatches) {
        $Functions += $Match.Groups[1].Value
    }
    
    return $Functions
}

function Get-ImportedModules {
    param([string]$ScriptPath)
    
    $Content = Get-Content $ScriptPath -Raw
    $ImportInfo = @{
        HasImports = $false
        ModulePaths = @()
        ModuleNames = @()
    }
    
    # Split content into lines and look for any Import-Module statements
    $Lines = $Content -split "`n"
    
    foreach ($Line in $Lines) {
        $Line = $Line.Trim()
        
        # Skip comments and empty lines
        if ($Line -match '^\s*#' -or $Line -match '^\s*$') {
            continue
        }
        
        # Look for any line that starts with Import-Module
        if ($Line -match '^Import-Module\s+') {
            $ImportInfo.HasImports = $true
            
            # Try to extract the actual path/directory being used
            if ($Line -match 'Join-Path\s+([^"]+)\s+"([^"]+\.psm1)"') {
                # Handle Join-Path expressions like: Import-Module (Join-Path $CommonModulesPath "Write-Status.psm1")
                $BasePath = $matches[1].Trim()
                $FileName = $matches[2]
                
                # Try to resolve common variable patterns
                if ($BasePath -match '\$CommonModulesPath' -or $BasePath -match '\$ModulesPath') {
                    # Look for the variable definition in the script to resolve the actual path
                    foreach ($SearchLine in $Lines) {
                        # Look for $CommonModulesPath = Join-Path -Path $PowershellDir -ChildPath "modules"
                        if ($SearchLine -match '\$CommonModulesPath\s*=\s*Join-Path.*"modules"') {
                            # This suggests a modules directory relative to the PowerShell root
                            # Try to resolve based on script location
                            $ScriptDir = Split-Path $ScriptPath -Parent
                            
                            # Try different resolution patterns based on script location
                            $ResolvedModulesPath = $null
                            
                            # Pattern 1: Programming\Powershell\ISD\Active_Directory\script.ps1 -> Programming\Powershell\modules
                            if ($ScriptDir -match '\\Powershell\\.*') {
                                $PowerShellDir = $ScriptDir -replace '\\Powershell\\.*', '\Powershell'
                                $ResolvedModulesPath = Join-Path $PowerShellDir "modules"
                            }
                            # Pattern 2: Programming\script.ps1 -> Programming\Powershell\modules
                            elseif ($ScriptDir -match '\\Programming$') {
                                $ResolvedModulesPath = Join-Path $ScriptDir "Powershell\modules"
                            }
                            # Pattern 3: Generic fallback - go up one level and look for modules
                            else {
                                $ParentDir = Split-Path $ScriptDir -Parent
                                $ResolvedModulesPath = Join-Path $ParentDir "modules"
                            }
                            
                            if ($ResolvedModulesPath -and (Test-Path $ResolvedModulesPath)) {
                                $ImportInfo.ModulePaths += $ResolvedModulesPath
                            }
                            break
                        }
                        # Also check for simpler patterns like $ModulesPath = "C:\Path\modules"
                        elseif ($SearchLine -match '\$(?:CommonModulesPath|ModulesPath)\s*=\s*"([^"]+)"') {
                            $ResolvedPath = $matches[1]
                            if (Test-Path $ResolvedPath) {
                                $ImportInfo.ModulePaths += $ResolvedPath
                            }
                            break
                        }
                    }
                }
                
                $ModuleName = [System.IO.Path]::GetFileNameWithoutExtension($FileName)
                if ($ModuleName -notin $ImportInfo.ModuleNames) {
                    $ImportInfo.ModuleNames += $ModuleName
                }
            }
            elseif ($Line -match 'Import-Module\s+"([^"]+\.psm1)"') {
                # Handle direct file paths like: Import-Module "C:\Path\Module.psm1"
                $FullPath = $matches[1]
                $Directory = Split-Path $FullPath -Parent
                if ($Directory -and (Test-Path $Directory) -and $Directory -notin $ImportInfo.ModulePaths) {
                    $ImportInfo.ModulePaths += $Directory
                }
                
                $ModuleName = [System.IO.Path]::GetFileNameWithoutExtension($FullPath)
                if ($ModuleName -notin $ImportInfo.ModuleNames) {
                    $ImportInfo.ModuleNames += $ModuleName
                }
            }
            elseif ($Line -match '^Import-Module\s+(?:-Name\s+)?([a-zA-Z0-9_.-]+)(?:\s|$)') {
                # Handle simple module names like: Import-Module ModuleName
                $ModuleName = $matches[1]
                if ($ModuleName -notin $ImportInfo.ModuleNames) {
                    $ImportInfo.ModuleNames += $ModuleName
                }
            }
        }
    }
    
    return $ImportInfo
}

function Get-ModuleFunctions {
    param(
        [string]$ScriptPath,
        [string]$ModulePath = $null
    )
    
    $ModuleFunctions = @{}
    $SearchPaths = @()
    
    # Get import information from the script
    $ImportInfo = Get-ImportedModules -ScriptPath $ScriptPath
    $HasImportStatements = $ImportInfo.HasImports
    
    # If script has Import-Module statements or ModulePath is specified, search for modules
    if ($HasImportStatements -or $ModulePath) {
        
        # Add paths extracted from Import-Module statements first (highest priority)
        $SearchPaths += $ImportInfo.ModulePaths
        
        # Add script directory
        $ScriptDir = Split-Path $ScriptPath -Parent
        $SearchPaths += $ScriptDir
        
        # Add manually specified module path if provided
        if ($ModulePath -and (Test-Path $ModulePath)) {
            $SearchPaths += $ModulePath
        }
        
        # Add common PowerShell module search paths (lower priority)
        $SearchPaths += $env:PSModulePath -split ';'
        
        # Remove duplicates and invalid paths
        $SearchPaths = $SearchPaths | Where-Object { $_ -and (Test-Path $_) } | Select-Object -Unique
        
        # Search for modules in all paths
        foreach ($Path in $SearchPaths) {
            # Look for .psm1 files
            $ModuleFiles = Get-ChildItem -Path $Path -Filter "*.psm1" -File -ErrorAction SilentlyContinue
            foreach ($File in $ModuleFiles) {
                $ModuleName = [System.IO.Path]::GetFileNameWithoutExtension($File.Name)
                
                if (-not $ModuleFunctions.ContainsKey($ModuleName)) {
                    $Functions = Get-ScriptFunctionDefinitions -FilePath $File.FullName
                    if ($Functions.Count -gt 0) {
                        $ModuleFunctions[$ModuleName] = $Functions
                    }
                }
            }
            
            # Also look for modules in subdirectories (standard PowerShell module structure)
            $ModuleDirectories = Get-ChildItem -Path $Path -Directory -ErrorAction SilentlyContinue
            foreach ($Dir in $ModuleDirectories) {
                $ModuleName = $Dir.Name
                $ModuleFile = Join-Path $Dir.FullName "$ModuleName.psm1"
                if (Test-Path $ModuleFile) {
                    if (-not $ModuleFunctions.ContainsKey($ModuleName)) {
                        $Functions = Get-ScriptFunctionDefinitions -FilePath $ModuleFile
                        if ($Functions.Count -gt 0) {
                            $ModuleFunctions[$ModuleName] = $Functions
                        }
                    }
                }
            }
        }
    }
    
    return $moduleFunctions
}

function Get-UserDefinedFunctionCalls {
    param([string]$FilePath, [array]$AvailableFunctions)
    
    $Content = Get-Content $FilePath -Raw
    $Calls = @()
    
    # Look for function calls that aren't built-in cmdlets
    # Pattern: function name at start of line or after whitespace, followed by parameters
    $CallPattern = '(?m)^\s*([A-Z][a-zA-Z0-9_-]*(?:-[a-zA-Z0-9_-]+)*)\s+(?![=<>!])'
    $CallMatches = [regex]::Matches($Content, $CallPattern)
    
    foreach ($Match in $CallMatches) {
        $FunctionName = $Match.Groups[1].Value
        
        # Skip well-known built-in cmdlets and PowerShell keywords
        $BuiltInCmdlets = @(
            'Get-Content', 'Set-Content', 'Get-Item', 'Set-Item', 'Get-ItemProperty', 'Set-ItemProperty',
            'Get-ChildItem', 'Get-Location', 'Set-Location', 'Get-Process', 'Stop-Process', 'Start-Process',
            'Get-Service', 'Start-Service', 'Stop-Service', 'Restart-Service', 'Set-Service',
            'New-Item', 'Remove-Item', 'Copy-Item', 'Move-Item', 'Rename-Item',
            'Write-Host', 'Write-Output', 'Write-Warning', 'Write-Error', 'Write-Verbose', 'Write-Debug',
            'Read-Host', 'Out-Host', 'Out-File', 'Out-Null', 'Out-String',
            'Select-Object', 'Where-Object', 'Sort-Object', 'Group-Object', 'Measure-Object',
            'ForEach-Object', 'Tee-Object', 'Compare-Object',
            'Import-Module', 'Export-Module', 'Get-Module', 'Remove-Module',
            'Test-Path', 'Resolve-Path', 'Split-Path', 'Join-Path',
            'Format-Table', 'Format-List', 'Format-Wide', 'Format-Custom',
            'ConvertTo-Json', 'ConvertFrom-Json', 'ConvertTo-Csv', 'ConvertFrom-Csv',
            'Export-Csv', 'Import-Csv', 'Export-Clixml', 'Import-Clixml',
            'Add-Member', 'Add-Type', 'Clear-Variable', 'Clear-Host',
            'Enable-WindowsOptionalFeature', 'Disable-WindowsOptionalFeature',
            'Get-WindowsOptionalFeature', 'Get-NetFirewallRule', 'New-NetFirewallRule',
            'Add-LocalGroupMember', 'Remove-LocalGroupMember', 'Get-LocalUser', 'New-LocalUser',
            'Get-Acl', 'Set-Acl', 'Get-ExecutionPolicy', 'Set-ExecutionPolicy'
        )
        
        $Keywords = @('if', 'else', 'elseif', 'foreach', 'while', 'do', 'switch', 'try', 'catch', 'finally', 
            'param', 'function', 'return', 'exit', 'break', 'continue', 'throw')
        
        if ($FunctionName -notin $BuiltInCmdlets -and $FunctionName -notin $Keywords) {
            
            if ($FunctionName -notin $Calls -and $FunctionName -in $AvailableFunctions) {
                $Calls += $FunctionName
            }
        }
    }
    
    return $Calls
}

function Get-CustomModules {
    <#
    .SYNOPSIS
        Dynamically gets the list of custom modules from the modules directory
    .DESCRIPTION
        Scans the modules directory for .psm1 and .ps1 files and returns their base names
        This ensures the custom modules list is always up-to-date with actual files
    #>
    
    # Try to determine the modules directory path relative to the script
    $ScriptDir = $PSScriptRoot
    if (-not $ScriptDir) {
        $ScriptDir = Split-Path $MyInvocation.MyCommand.Path -Parent
    }
    
    # The modules directory should be where this script is located
    $ModulesDir = $ScriptDir
    
    # Get all .psm1 and .ps1 files in the modules directory (excluding this script)
    $CustomModules = @()
    if (Test-Path $ModulesDir) {
        $ThisScriptName = [System.IO.Path]::GetFileNameWithoutExtension($MyInvocation.MyCommand.Name)
        
        # Get .psm1 files
        $ModuleFiles = Get-ChildItem -Path $ModulesDir -Filter "*.psm1" -File -ErrorAction SilentlyContinue
        foreach ($File in $ModuleFiles) {
            $ModuleName = [System.IO.Path]::GetFileNameWithoutExtension($File.Name)
            $CustomModules += $ModuleName
        }
        
        # Get .ps1 files (excluding this script and common utility files)
        $ScriptFiles = Get-ChildItem -Path $ModulesDir -Filter "*.ps1" -File -ErrorAction SilentlyContinue
        foreach ($File in $ScriptFiles) {
            $ModuleName = [System.IO.Path]::GetFileNameWithoutExtension($File.Name)
            # Exclude this script and other non-module files
            if ($ModuleName -ne $ThisScriptName -and $ModuleName -ne "README") {
                $CustomModules += $ModuleName
            }
        }
    }
    
    return $CustomModules
}

function Test-FunctionAvailability {
    param([string]$FilePath, [hashtable]$ModuleFunctions)
    
    if ($Quick) {
        return @{ Available = $true; Missing = @(); Found = @() }
    }

    Write-ValidationResult "Checking function dependencies..." "INFO"
    
    # Get all functions defined in the script
    $ScriptFunctions = Get-ScriptFunctionDefinitions -FilePath $FilePath
    
    # Get custom modules dynamically from the modules directory
    $CustomModules = Get-CustomModules
    
    # Get all functions available from modules, separating custom vs system
    $AllModuleFunctions = @()
    $CustomModuleFunctions = @()
    
    foreach ($ModuleEntry in $ModuleFunctions.GetEnumerator()) {
        $ModuleName = $ModuleEntry.Key
        $Functions = $ModuleEntry.Value
        
        $AllModuleFunctions += $Functions
        
        if ($CustomModules -contains $ModuleName) {
            $CustomModuleFunctions += $Functions
        }
    }
    
    # All available functions
    $AllAvailableFunctions = $ScriptFunctions + $AllModuleFunctions
    
    # Get function calls in the script
    $FunctionCalls = Get-UserDefinedFunctionCalls -FilePath $FilePath -AvailableFunctions $AllAvailableFunctions
    
    $Missing = @()
    $Found = @()
    
    foreach ($Call in $FunctionCalls) {
        if ($Call -in $AllAvailableFunctions) {
            $Found += $Call
        } else {
            $Missing += $Call
        }
    }
    
    if ($Missing.Count -eq 0) {
        Write-ValidationResult "All function dependencies satisfied" "SUCCESS" 1
    } else {
        Write-ValidationResult "Missing function dependencies ($($Missing.Count))" "WARNING" 1
        foreach ($Func in $Missing) {
            Write-ValidationResult "Function '$Func' not found" "WARNING" 2
        }
    }
    
    if ($Detailed) {
        Write-ValidationResult "Script functions: $($ScriptFunctions -join ', ')" "INFO" 1
        
        if ($ShowAllModules) {
            Write-ValidationResult "Module functions: $($AllModuleFunctions -join ', ')" "INFO" 1
        } else {
            if ($CustomModuleFunctions.Count -gt 0) {
                Write-ValidationResult "Custom module functions: $($CustomModuleFunctions -join ', ')" "INFO" 1
            }
            $SystemFunctionCount = $AllModuleFunctions.Count - $CustomModuleFunctions.Count
            if ($SystemFunctionCount -gt 0) {
                Write-ValidationResult "System module functions: $SystemFunctionCount functions hidden (use -ShowAllModules to show all)" "INFO" 1
            }
        }
        
        Write-ValidationResult "Called functions: $($Found -join ', ')" "INFO" 1
    }
    
    return @{ 
        Available = ($Missing.Count -eq 0)
        Missing = $Missing
        Found = $Found
        ScriptFunctions = $ScriptFunctions
        ModuleFunctions = $AllModuleFunctions
    }
}

function Test-CommonFormattingIssues {
    param([string]$FilePath)
    
    if ($Quick) {
        return @{ HasIssues = $false; Issues = @() }
    }
    
    Write-ValidationResult "Checking for formatting issues..." "INFO"
    
    $Content = Get-Content $FilePath
    $Issues = @()
    $LineNumber = 1
    
    foreach ($Line in $Content) {
        # Skip comment lines and empty lines
        if ($Line -match '^\s*#' -or $Line -match '^\s*$' -or $Line -match '^\s*<#' -or $Line -match '^\s*\.') {
            $LineNumber++
            continue
        }
        
        # Check for functions calls that might be on the same line as other commands
        # Look for patterns like: something; Function-Name but exclude } else { patterns
        if (($Line -match ';\s*[A-Z][a-zA-Z0-9_-]*(-[a-zA-Z0-9_-]+)?\s+[^=<>!]' -and $Line -notmatch '} else {') -or 
            ($Line -match '\}\s*[A-Z][a-zA-Z0-9_-]*(-[a-zA-Z0-9_-]+)?\s+[^=<>!]' -and $Line -notmatch '} else {')) {
            $Issues += "Line $LineNumber`: Possible command continuation issue - consider separating commands"
        }
        
        $LineNumber++
    }
    
    if ($Issues.Count -eq 0) {
        Write-ValidationResult "No formatting issues found" "SUCCESS" 1
    } else {
        Write-ValidationResult "Formatting issues found ($($Issues.Count))" "WARNING" 1
        foreach ($Issue in $Issues) {
            Write-ValidationResult $Issue "WARNING" 2
        }
    }
    
    return @{ HasIssues = ($Issues.Count -gt 0); Issues = $Issues }
}

# Main execution
Write-Host ""
Write-Host "PowerShell Script Validation Tool" -ForegroundColor Magenta
Write-Host "=================================" -ForegroundColor Magenta
Write-Host ""

$ScriptName = Split-Path $ScriptPath -Leaf
Write-ValidationResult "Analyzing: $ScriptName" "INFO"
Write-Host ""

# Test syntax first
$SyntaxResult = Test-PowerShellSyntax -FilePath $ScriptPath

if (-not $SyntaxResult.Valid) {
    Write-Host ""
    Write-ValidationResult "Script has syntax errors. Please fix these first." "ERROR"
    exit 1
}

if ($Quick) {
    Write-Host ""
    Write-ValidationResult "Quick syntax check completed successfully!" "SUCCESS"
    exit 0
}

Write-Host ""

# Get available modules (automatically detect imports + optional manual path)
$ModuleFunctions = Get-ModuleFunctions -ScriptPath $ScriptPath -ModulePath $ModulePath

# Get custom modules dynamically from the modules directory
$CustomModules = Get-CustomModules

if ($ModuleFunctions.Count -gt 0) {
    # Count custom and system modules
    $CustomCount = 0
    $SystemCount = 0
    $DisplayedModules = @{}
    
    foreach ($Module in $ModuleFunctions.GetEnumerator()) {
        if ($CustomModules -contains $Module.Key) {
            $CustomCount++
            $DisplayedModules[$Module.Key] = $Module.Value
        } else {
            $SystemCount++
        }
    }
    
    $TotalCount = $ModuleFunctions.Count
    
    if ($SystemCount -gt 0) {
        Write-ValidationResult "Found $TotalCount available modules ($CustomCount custom, $SystemCount system modules)" "INFO"
    } else {
        Write-ValidationResult "Found $TotalCount available modules" "INFO"
    }
    
    if ($Detailed) {
        if ($ShowAllModules) {
            # Show all modules when ShowAllModules is specified
            foreach ($Module in $ModuleFunctions.GetEnumerator()) {
                Write-ValidationResult "Module: $($Module.Key) ($($Module.Value.Count) functions)" "INFO" 1
            }
        } else {
            # Show only custom modules by default
            if ($DisplayedModules.Count -gt 0) {
                Write-ValidationResult "Custom modules:" "INFO" 1
                foreach ($Module in $DisplayedModules.GetEnumerator()) {
                    Write-ValidationResult "Module: $($Module.Key) ($($Module.Value.Count) functions)" "INFO" 2
                }
            }
            if ($SystemCount -gt 0) {
                Write-ValidationResult "System modules: $SystemCount modules hidden (use -ShowAllModules to show all)" "INFO" 1
            }
        }
    }
} else {
    Write-ValidationResult "No modules found for dependency checking" "INFO"
}

Write-Host ""

# Test function dependencies
$FunctionResult = Test-FunctionAvailability -FilePath $ScriptPath -ModuleFunctions $ModuleFunctions

Write-Host ""

# Test formatting issues
$FormattingResult = Test-CommonFormattingIssues -FilePath $ScriptPath

Write-Host ""

# Summary
if ($SyntaxResult.Valid -and -not $FormattingResult.HasIssues -and $FunctionResult.Available) {
    Write-ValidationResult "All validation checks passed!" "SUCCESS"
    exit 0
} elseif ($SyntaxResult.Valid) {
    $WarningCount = $FunctionResult.Missing.Count + $FormattingResult.Issues.Count
    Write-ValidationResult "Validation completed with $WarningCount warnings" "WARNING"
    exit 0
} else {
    Write-ValidationResult "Validation failed" "ERROR"
    exit 1
}
