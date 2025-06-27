<#
    .SYNOPSIS
        Invoke-PowerShellValidation - Advanced PowerShell script validation tool

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

    .PARAMETER AnalyzerSeverity
        PSScriptAnalyzer severity levels to include. Valid values: Error, Warning, Information.
        Defaults to Error and Warning. Use 'Information' for detailed code style analysis.

    .EXAMPLE
        Invoke-PowerShellValidation -ScriptPath "C:\Scripts\MyScript.ps1"

    .EXAMPLE
        Invoke-PowerShellValidation -ScriptPath "C:\Scripts\MyScript.ps1" -ModulePath "C:\Modules" -Detailed

    .EXAMPLE
        Invoke-PowerShellValidation -ScriptPath "C:\Scripts\MyScript.ps1" -Detailed -ShowAllModules

    .EXAMPLE
        Invoke-PowerShellValidation -ScriptPath "C:\Scripts\MyScript.ps1" -AnalyzerSeverity @("Error", "Warning", "Information")
        Runs comprehensive analysis including informational style recommendations

    .EXAMPLE
        Invoke-PowerShellValidation -ScriptPath "C:\Scripts\MyScript.ps1" -Detailed -ShowAllModules
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
    [switch]$ShowAllModules,
    
    [Parameter(Mandatory = $false)]
    [ValidateSet("Error", "Warning", "Information")]
    [string[]]$AnalyzerSeverity = @("Error", "Warning")
)

function Write-ValidationResult {
    <#
        .SYNOPSIS
            Writes validation messages with color-coded output, icons, and optional indentation.
        
        .DESCRIPTION
            Enhanced validation output function that combines timestamped logging with visual indicators.
            Based on the Write-Status function pattern but optimized for validation reporting.
            Supports indentation for hierarchical output and uses icons for quick visual feedback.
        
        .PARAMETER Message
            The validation message to display.
        
        .PARAMETER Type
            The type of validation result. Valid values are:
            - SUCCESS: Green text with [+] icon
            - ERROR: Red text with [X] icon  
            - WARNING: Yellow text with [!] icon
            - INFO: Cyan text with [i] icon
        
        .PARAMETER Indent
            The indentation level (number of spaces = Indent * 2). Defaults to 0.
        
        .PARAMETER ShowTimestamp
            When specified, includes a timestamp in the output. Useful for detailed logging.
        
        .EXAMPLE
            Write-ValidationResult "Syntax validation passed" "SUCCESS" 1
            Displays: "  [+] Syntax validation passed" in green
        
        .EXAMPLE
            Write-ValidationResult "Starting validation..." "INFO" 0 -ShowTimestamp
            Displays: "[2025-06-27 10:30:15] [i] Starting validation..." in cyan
        
        .EXAMPLE
            Write-ValidationResult "Line 42: Missing semicolon" "ERROR" 2
            Displays: "    [X] Line 42: Missing semicolon" in red
    #>
    
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,
        
        [Parameter(Mandatory = $true)]
        [ValidateSet("SUCCESS", "ERROR", "WARNING", "INFO")]
        [string]$Type,
        
        [Parameter(Mandatory = $false)]
        [int]$Indent = 0,
        
        [Parameter(Mandatory = $false)]
        [switch]$ShowTimestamp
    )
    
    # Create indentation string
    $IndentStr = "  " * $Indent
    
    # Set icon based on type
    $Icon = switch ($Type) {
        "SUCCESS" { "[+]" }
        "ERROR"   { "[X]" }
        "WARNING" { "[!]" }
        "INFO"    { "[i]" }
        default   { "[?]" }
    }
    
    # Set color based on type
    $Color = switch ($Type) {
        "SUCCESS" { "Green" }
        "ERROR"   { "Red" }
        "WARNING" { "Yellow" }
        "INFO"    { "Cyan" }
        default   { "White" }
    }
    
    # Build output string
    if ($ShowTimestamp) {
        $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        $OutputMessage = "$IndentStr[$Timestamp] $Icon $Message"
    }
    else {
        $OutputMessage = "$IndentStr$Icon $Message"
    }
    
    Write-Host $OutputMessage -ForegroundColor $Color
}

function Test-PowerShellSyntax {
    <#
        .SYNOPSIS
            Tests PowerShell script syntax for errors and validity.
        
        .DESCRIPTION
            Validates PowerShell script syntax using the .NET Language Parser.
            Returns detailed information about any syntax errors found including
            line numbers and error messages. This function performs static analysis
            without executing the script.
        
        .PARAMETER FilePath
            The full path to the PowerShell script file to validate.
        
        .OUTPUTS
            Returns a hashtable with:
            - Valid: Boolean indicating if syntax is valid
            - Errors: Array of syntax error objects with line numbers and messages
        
        .EXAMPLE
            $Result = Test-PowerShellSyntax -FilePath "C:\Scripts\MyScript.ps1"
            if ($Result.Valid) { Write-Host "Syntax is valid" }
        
        .EXAMPLE
            Test-PowerShellSyntax ".\Install-SamClient.ps1"
            Validates syntax and displays results with colored output
        
        .NOTES
            Uses the .NET Framework Language Parser for accurate syntax validation.
            Does not execute the script, only parses it for syntax correctness.
    #>
    
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$FilePath
    )
    
    Write-ValidationResult "Validating PowerShell syntax..." "INFO" 0 -ShowTimestamp
    
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
    <#
        .SYNOPSIS
            Extracts function definitions from a PowerShell script file.
        
        .DESCRIPTION
            Parses a PowerShell script to identify all function definitions using regex pattern matching.
            Returns an array of function names found in the script. Handles various function declaration
            styles including those with parameters and different formatting.
        
        .PARAMETER FilePath
            The full path to the PowerShell script file to analyze.
        
        .OUTPUTS
            Returns an array of strings containing the names of all functions defined in the script.
        
        .EXAMPLE
            $Functions = Get-ScriptFunctionDefinitions -FilePath "C:\Scripts\MyModule.psm1"
            Write-Host "Found functions: $($Functions -join ', ')"
        
        .EXAMPLE
            Get-ScriptFunctionDefinitions ".\Invoke-PowerShellValidation.ps1"
            Returns: @("Write-ValidationResult", "Test-PowerShellSyntax", "Get-ScriptFunctionDefinitions", ...)
        
        .NOTES
            Uses regex pattern matching to identify function declarations.
            Supports various PowerShell function declaration formats.
    #>
    
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$FilePath
    )
    
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
    <#
        .SYNOPSIS
            Analyzes a PowerShell script to detect imported modules and their paths.
        
        .DESCRIPTION
            Parses a PowerShell script to identify Import-Module statements and extract
            module names and paths. Supports various Import-Module syntax patterns including
            simple names, quoted paths, Join-Path constructions, and variable references.
            Returns detailed information about module imports found in the script.
        
        .PARAMETER ScriptPath
            The full path to the PowerShell script file to analyze for module imports.
        
        .OUTPUTS
            Returns a hashtable containing:
            - HasImports: Boolean indicating if any Import-Module statements were found
            - ModulePaths: Array of file paths to modules being imported
            - ModuleNames: Array of module names being imported
        
        .EXAMPLE
            $ImportInfo = Get-ImportedModules -ScriptPath "C:\Scripts\MyScript.ps1"
            if ($ImportInfo.HasImports) {
                Write-Host "Modules imported: $($ImportInfo.ModuleNames -join ', ')"
            }
        
        .EXAMPLE
            Get-ImportedModules ".\Install-SamClient.ps1"
            Analyzes the script for any Import-Module statements
        
        .NOTES
            Supports detection of various Import-Module patterns:
            - Import-Module ModuleName
            - Import-Module "C:\Path\To\Module.psm1" 
            - Import-Module (Join-Path $Path "Module.psm1")
            - Import-Module $VariablePath
    #>
    
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ScriptPath
    )
    
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
    <#
        .SYNOPSIS
            Discovers and catalogs functions from PowerShell modules referenced by a script.
        
        .DESCRIPTION
            Analyzes a PowerShell script to identify imported modules and discovers all functions
            available from those modules. Searches multiple paths including script directory,
            parent directories, and explicit module paths. Automatically detects custom modules
            and differentiates them from system modules.
        
        .PARAMETER ScriptPath
            The full path to the PowerShell script file to analyze for module dependencies.
        
        .PARAMETER ModulePath
            Optional explicit path to search for additional modules beyond those found in the script.
        
        .OUTPUTS
            Returns a hashtable where keys are module names and values are arrays of function names
            available from each module. Empty hashtable if no modules or functions are found.
        
        .EXAMPLE
            $ModuleFunctions = Get-ModuleFunctions -ScriptPath "C:\Scripts\MyScript.ps1"
            foreach ($Module in $ModuleFunctions.GetEnumerator()) {
                Write-Host "$($Module.Key): $($Module.Value.Count) functions"
            }
        
        .EXAMPLE
            Get-ModuleFunctions -ScriptPath ".\Test-Script.ps1" -ModulePath "C:\CustomModules"
            Searches for modules in the script plus an additional custom module directory
        
        .NOTES
            Searches for modules in the following order:
            1. Paths extracted from Import-Module statements in the script
            2. Script directory and parent directories
            3. Explicitly specified ModulePath parameter
            4. PowerShell module paths (PSModulePath)
    #>
    
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ScriptPath,
        
        [Parameter(Mandatory = $false)]
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
    <#
        .SYNOPSIS
            Identifies user-defined function calls within a PowerShell script.
        
        .DESCRIPTION
            Analyzes a PowerShell script to identify calls to user-defined functions,
            excluding built-in PowerShell cmdlets and keywords. Uses pattern matching
            to find function calls and filters them against a list of available functions
            from modules and script definitions.
        
        .PARAMETER FilePath
            The full path to the PowerShell script file to analyze for function calls.
        
        .PARAMETER AvailableFunctions
            Array of function names that are available (from modules and script definitions)
            to validate against when identifying function calls.
        
        .OUTPUTS
            Returns an array of strings containing the names of user-defined functions
            that are called within the script.
        
        .EXAMPLE
            $ScriptFunctions = Get-ScriptFunctionDefinitions -FilePath "MyScript.ps1"
            $ModuleFunctions = @("Write-Log", "Send-Email", "Get-Config")
            $AllFunctions = $ScriptFunctions + $ModuleFunctions
            $FunctionCalls = Get-UserDefinedFunctionCalls -FilePath "MyScript.ps1" -AvailableFunctions $AllFunctions
        
        .EXAMPLE
            Get-UserDefinedFunctionCalls -FilePath ".\Install-SamClient.ps1" -AvailableFunctions @("Write-Status", "Send-AnyKeyAndExit")
            Returns functions called in the script that match the available functions list
        
        .NOTES
            Excludes common PowerShell built-in cmdlets and keywords to focus on user-defined functions.
            Uses regex pattern matching to identify potential function calls.
    #>
    
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$FilePath,
        
        [Parameter(Mandatory = $true)]
        [array]$AvailableFunctions
    )
    
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
            Dynamically discovers custom PowerShell modules in the modules directory.
        
        .DESCRIPTION
            Scans the modules directory for PowerShell module files (.psm1 and .ps1) and returns
            their base names. This ensures the custom modules list is always up-to-date with actual
            files present in the directory. Used to differentiate custom modules from system modules
            for filtering and display purposes.
        
        .OUTPUTS
            Returns an array of strings containing the base names (without extensions) of all
            custom module files found in the modules directory.
        
        .EXAMPLE
            $CustomModules = Get-CustomModules
            Write-Host "Found custom modules: $($CustomModules -join ', ')"
        
        .EXAMPLE
            $CustomModules = Get-CustomModules
            if ($CustomModules -contains "Write-Status") {
                Write-Host "Write-Status module is available"
            }
        
        .NOTES
            - Searches for both .psm1 and .ps1 files in the modules directory
            - Returns base names without file extensions
            - Uses script location to determine modules directory path
            - Automatically adapts to new modules added to the directory
    #>
    
    [CmdletBinding()]
    param()
    
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
    <#
        .SYNOPSIS
            Tests the availability of function dependencies in a PowerShell script.
        
        .DESCRIPTION
            Analyzes a PowerShell script to determine if all called functions are available
            either through module imports or script definitions. Identifies missing function
            dependencies and provides detailed reporting of function availability status.
            Differentiates between custom modules and system modules for better analysis.
        
        .PARAMETER FilePath
            The full path to the PowerShell script file to analyze for function dependencies.
        
        .PARAMETER ModuleFunctions
            Hashtable of available module functions where keys are module names and values
            are arrays of function names available from each module.
        
        .OUTPUTS
            Returns a hashtable containing:
            - Available: Boolean indicating if all dependencies are satisfied
            - Missing: Array of function names that are called but not available
            - Found: Array of function names that are called and available
            - ScriptFunctions: Array of functions defined within the script
            - ModuleFunctions: Arrays of functions available from modules
        
        .EXAMPLE
            $ModuleFunctions = Get-ModuleFunctions -ScriptPath "MyScript.ps1"
            $Result = Test-FunctionAvailability -FilePath "MyScript.ps1" -ModuleFunctions $ModuleFunctions
            if (-not $Result.Available) {
                Write-Warning "Missing functions: $($Result.Missing -join ', ')"
            }
        
        .EXAMPLE
            Test-FunctionAvailability -FilePath ".\Install-SamClient.ps1" -ModuleFunctions @{}
            Analyzes the script for function dependencies even with no modules available
        
        .NOTES
            - Returns early with success status if Quick mode is enabled
            - Provides detailed output about script functions, module functions, and function calls
            - Separates custom modules from system modules for clearer reporting
    #>
    
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$FilePath,
        
        [Parameter(Mandatory = $true)]
        [hashtable]$ModuleFunctions
    )
    
    if ($Quick) {
        return @{ Available = $true; Missing = @(); Found = @() }
    }

    Write-ValidationResult "Checking function dependencies..." "INFO" 0 -ShowTimestamp
    
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
            # Show only custom modules by default
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
    <#
        .SYNOPSIS
            Analyzes a PowerShell script for common formatting and style issues.
        
        .DESCRIPTION
            Performs static analysis of PowerShell script formatting to identify common
            style issues such as inconsistent casing, improper spacing, and formatting
            violations. Helps maintain code quality and consistency across scripts.
            Focuses on PowerShell best practices and common style guidelines.
        
        .PARAMETER FilePath
            The full path to the PowerShell script file to analyze for formatting issues.
        
        .OUTPUTS
            Returns a hashtable containing:
            - HasIssues: Boolean indicating if any formatting issues were found
            - Issues: Array of strings describing specific formatting issues with line numbers
        
        .EXAMPLE
            $FormatResult = Test-CommonFormattingIssues -FilePath "C:\Scripts\MyScript.ps1"
            if ($FormatResult.HasIssues) {
                foreach ($Issue in $FormatResult.Issues) {
                    Write-Warning $Issue
                }
            }
        
        .EXAMPLE
            Test-CommonFormattingIssues -FilePath ".\Install-SamClient.ps1"
            Analyzes the script and reports any formatting issues found
        
        .NOTES
            - Returns early with no issues if Quick mode is enabled
            - Checks for common PowerShell formatting and style issues
            - Provides line-by-line analysis with specific issue descriptions
            - Focuses on maintainability and readability improvements
    #>
    
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$FilePath
    )
    
    if ($Quick) {
        return @{ HasIssues = $false; Issues = @() }
    }
    
    Write-ValidationResult "Checking for formatting issues..." "INFO" 0 -ShowTimestamp
    
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

function Test-PSScriptAnalyzer {
    <#
        .SYNOPSIS
            Analyzes PowerShell script using PSScriptAnalyzer for professional code quality checks.
        
        .DESCRIPTION
            Integrates PSScriptAnalyzer to provide comprehensive code analysis including formatting,
            best practices, security issues, and performance recommendations. Provides Prettier-like
            professional code quality analysis for PowerShell scripts.
        
        .PARAMETER FilePath
            The full path to the PowerShell script file to analyze with PSScriptAnalyzer.
        
        .PARAMETER IncludeDefaultRules
            Include default PSScriptAnalyzer rules (recommended for most scenarios).
        
        .PARAMETER Severity
            Array of severity levels to include. Valid values: Error, Warning, Information.
            Defaults to @("Error", "Warning") for important issues only.
        
        .OUTPUTS
            Returns a hashtable containing:
            - Available: Boolean indicating if PSScriptAnalyzer is available
            - HasIssues: Boolean indicating if any issues were found
            - Issues: Array of PSScriptAnalyzer issue objects with details
            - Summary: String summary of issues found
        
        .EXAMPLE
            $AnalyzerResult = Test-PSScriptAnalyzer -FilePath "C:\Scripts\MyScript.ps1"
            if ($AnalyzerResult.HasIssues) {
                Write-Host $AnalyzerResult.Summary
            }
        
        .EXAMPLE
            Test-PSScriptAnalyzer -FilePath ".\MyScript.ps1" -Severity @("Error", "Warning", "Information")
            Analyzes script with all severity levels including informational messages
        
        .NOTES
            - Requires PSScriptAnalyzer module to be installed
            - Automatically installs PSScriptAnalyzer if not present and user consents
            - Provides detailed issue reporting with line numbers and remediation suggestions
    #>
    
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$FilePath,
        
        [Parameter(Mandatory = $false)]
        [switch]$IncludeDefaultRules = $true,
        
        [Parameter(Mandatory = $false)]
        [ValidateSet("Error", "Warning", "Information")]
        [string[]]$Severity = @("Error", "Warning")
    )
    
    if ($Quick) {
        return @{ Available = $false; HasIssues = $false; Issues = @(); Summary = "Skipped in Quick mode" }
    }
    
    Write-ValidationResult "Running PSScriptAnalyzer code quality checks..." "INFO" 0 -ShowTimestamp
    
    # Check if PSScriptAnalyzer is available
    $PSScriptAnalyzerModule = Get-Module -ListAvailable -Name PSScriptAnalyzer
    
    if (-not $PSScriptAnalyzerModule) {
        Write-ValidationResult "PSScriptAnalyzer module not found" "WARNING" 1
        $InstallChoice = Read-Host "Would you like to install PSScriptAnalyzer for enhanced code analysis? (Y/N)"
        
        if ($InstallChoice -eq "Y" -or $InstallChoice -eq "y") {
            try {
                Write-ValidationResult "Installing PSScriptAnalyzer module..." "INFO" 1
                Install-Module -Name PSScriptAnalyzer -Scope CurrentUser -Force -AllowClobber
                Write-ValidationResult "PSScriptAnalyzer installed successfully" "SUCCESS" 1
            }
            catch {
                Write-ValidationResult "Failed to install PSScriptAnalyzer: $($_.Exception.Message)" "ERROR" 1
                return @{ Available = $false; HasIssues = $false; Issues = @(); Summary = "PSScriptAnalyzer not available" }
            }
        }
        else {
            Write-ValidationResult "Skipping PSScriptAnalyzer checks" "INFO" 1
            return @{ Available = $false; HasIssues = $false; Issues = @(); Summary = "PSScriptAnalyzer not available" }
        }
    }
    
    try {
        # Import the module
        Import-Module PSScriptAnalyzer -Force
        
        # Run PSScriptAnalyzer with specified parameters
        $AnalyzerParams = @{
            Path = $FilePath
            Severity = $Severity
        }
        
        if ($IncludeDefaultRules) {
            $AnalyzerParams.IncludeDefaultRules = $true
        }
        
        $Results = Invoke-ScriptAnalyzer @AnalyzerParams
        
        if ($Results.Count -eq 0) {
            Write-ValidationResult "No PSScriptAnalyzer issues found" "SUCCESS" 1
            return @{ 
                Available = $true
                HasIssues = $false
                Issues = @()
                Summary = "Code meets PSScriptAnalyzer standards"
            }
        }
        else {
            # Group issues by severity
            $ErrorCount = ($Results | Where-Object { $_.Severity -eq "Error" }).Count
            $WarningCount = ($Results | Where-Object { $_.Severity -eq "Warning" }).Count
            $InfoCount = ($Results | Where-Object { $_.Severity -eq "Information" }).Count
            
            $SummaryParts = @()
            if ($ErrorCount -gt 0) { $SummaryParts += "$ErrorCount error(s)" }
            if ($WarningCount -gt 0) { $SummaryParts += "$WarningCount warning(s)" }
            if ($InfoCount -gt 0) { $SummaryParts += "$InfoCount info message(s)" }
            
            $Summary = "PSScriptAnalyzer found $($Results.Count) issue(s): $($SummaryParts -join ', ')"
            Write-ValidationResult $Summary "WARNING" 1
            
            # Display detailed issues
            foreach ($Issue in $Results) {
                $SeverityLevel = switch ($Issue.Severity) {
                    "Error" { "ERROR" }
                    "Warning" { "WARNING" }
                    "Information" { "INFO" }
                    default { "INFO" }
                }
                
                $IssueMessage = "Line $($Issue.Line): [$($Issue.RuleName)] $($Issue.Message)"
                Write-ValidationResult $IssueMessage $SeverityLevel 2
                
                if ($Issue.SuggestedCorrections) {
                    Write-ValidationResult "Suggested fix available" "INFO" 3
                }
            }
            
            return @{
                Available = $true
                HasIssues = $true
                Issues = $Results
                Summary = $Summary
            }
        }
    }
    catch {
        Write-ValidationResult "Failed to run PSScriptAnalyzer: $($_.Exception.Message)" "ERROR" 1
        return @{ Available = $false; HasIssues = $false; Issues = @(); Summary = "PSScriptAnalyzer failed to run" }
    }
}

### Main execution ###
Write-Host ""
Write-Host "PowerShell Script Validation Tool" -ForegroundColor Magenta
Write-Host "====================================" -ForegroundColor Magenta
Write-Host ""

$ScriptName = Split-Path $ScriptPath -Leaf
Write-ValidationResult "Analyzing: $ScriptName" "INFO" 0 -ShowTimestamp
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

# Test PSScriptAnalyzer
$PSScriptAnalyzerResult = Test-PSScriptAnalyzer -FilePath $ScriptPath -IncludeDefaultRules:$Detailed -Severity $AnalyzerSeverity

Write-Host ""

# Summary
if ($SyntaxResult.Valid -and -not $FormattingResult.HasIssues -and $FunctionResult.Available -and -not $PSScriptAnalyzerResult.HasIssues) {
    Write-ValidationResult "All validation checks passed!" "SUCCESS" 0 -ShowTimestamp
    exit 0
} elseif ($SyntaxResult.Valid) {
    $WarningCount = $FunctionResult.Missing.Count + $FormattingResult.Issues.Count + $PSScriptAnalyzerResult.Issues.Count
    Write-ValidationResult "Validation completed with $WarningCount warnings" "WARNING"
    exit 0
} else {
    Write-ValidationResult "Validation failed" "ERROR"
    exit 1
}
