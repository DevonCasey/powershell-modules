# Test-PowerShellSyntax.ps1

A comprehensive PowerShell script validation tool that checks syntax, function dependencies, and common formatting issues. Designed to work seamlessly with modular PowerShell environments.

## Features

### Core Validation

- **Syntax Validation**: Uses PowerShell's built-in parser to detect syntax errors
- **Function Dependency Checking**: Validates that all called functions are available
- **Formatting Analysis**: Identifies common formatting issues and potential problems
- **Module Detection**: Automatically detects and analyzes Import-Module statements

### Smart Module Discovery

- **Automatic Path Detection**: Extracts module paths from Import-Module statements
- **Variable Resolution**: Resolves module path variables (e.g., `$CommonModulesPath`, `$ModulesPath`)
- **Multiple Import Patterns**: Supports various Import-Module syntaxes:
  - Simple names: `Import-Module ModuleName`
  - Direct paths: `Import-Module "C:\Path\Module.psm1"`
  - Join-Path expressions: `Import-Module (Join-Path $Path "Module.psm1")`
  - Variable assignments and complex expressions

### Custom vs System Module Filtering

- **Smart Filtering**: Distinguishes between custom and system modules
- **Dynamic Detection**: Automatically discovers custom modules from the modules directory
- **Clean Output**: Shows only relevant custom modules by default
- **Override Option**: Use `-ShowAllModules` to display all modules including system ones

### Code Quality

- **PascalCase Compliance**: All functions, variables, and parameters follow PowerShell best practices
- **Robust Error Handling**: Graceful handling of missing files, invalid paths, and parsing errors
- **Comprehensive Logging**: Clear, color-coded output with detailed validation results

## Parameters

| Parameter        | Type   | Required | Description                                                                |
| ---------------- | ------ | -------- | -------------------------------------------------------------------------- |
| `ScriptPath`     | String | Yes      | Path to the PowerShell script file to validate                             |
| `ModulePath`     | String | No       | Optional additional path to search for modules (auto-detected from script) |
| `Quick`          | Switch | No       | Perform only syntax validation (fastest check)                             |
| `Detailed`       | Switch | No       | Show detailed information about functions and dependencies                 |
| `ShowAllModules` | Switch | No       | Show all modules including system modules (normally filtered out)          |

## Usage Examples

### Basic Syntax Check

```powershell
.\Test-PowerShellSyntax.ps1 -ScriptPath "C:\Scripts\MyScript.ps1"
```

### Quick Syntax Validation Only

```powershell
.\Test-PowerShellSyntax.ps1 -ScriptPath "C:\Scripts\MyScript.ps1" -Quick
```

### Detailed Analysis with Custom Module Path

```powershell
.\Test-PowerShellSyntax.ps1 -ScriptPath "C:\Scripts\MyScript.ps1" -ModulePath "C:\CustomModules" -Detailed
```

### Show All Modules (Including System)

```powershell
.\Test-PowerShellSyntax.ps1 -ScriptPath "C:\Scripts\MyScript.ps1" -Detailed -ShowAllModules
```

### Real-World Example

```powershell
# Validate Install-SamClient.ps1 with detailed output
.\Test-PowerShellSyntax.ps1 -ScriptPath "C:\Users\dcasey\Documents\Programming\Powershell\WCL\PublicPCs\scripts\Install-SamClient.ps1" -Detailed
```

## Sample Output

```
PowerShell Script Validation Tool
=================================

[i] Analyzing: Install-SamClient.ps1

[+] Syntax validation passed

[i] Found 9 available modules (9 custom, 0 system modules)

[+] All function dependencies satisfied
[i] Script functions: Write-Status
[i] Custom module functions: Write-Status, Copy-FilesToTempDirectory, Get-AllPrinters, Invoke-AdminElevation, Remove-TempFiles, Send-AnyKeyAndExit, Add-FirewallRule, Begin-Robocopy
[i] Called functions: Write-Status

[+] No formatting issues found

[+] All validation checks passed!
```

## How It Works

### Module Path Detection

1. **Script Analysis**: Scans the target script for Import-Module statements
2. **Variable Resolution**: Resolves common variable patterns like `$CommonModulesPath`
3. **Path Extraction**: Extracts actual module directories from various Import-Module syntaxes
4. **Automatic Discovery**: Searches standard PowerShell module paths and script-relative locations

### Function Dependency Validation

1. **Function Extraction**: Identifies all function definitions in the script and imported modules
2. **Call Analysis**: Finds function calls within the script using pattern matching
3. **Dependency Mapping**: Maps function calls to available functions
4. **Missing Detection**: Reports any undefined function dependencies

### Smart Filtering System

- **Custom Module Detection**: Dynamically scans the modules directory for .psm1 and .ps1 files
- **System Module Exclusion**: Filters out common system modules to reduce noise
- **Override Capability**: Provides `-ShowAllModules` switch for complete visibility

## Recent Updates (v2.0)

### Version 2.0 - June 2025

- ✅ **Complete PascalCase Conversion**: All functions, variables, and parameters now follow PowerShell naming conventions
- ✅ **Enhanced Module Detection**: Improved Import-Module statement parsing with support for complex expressions
- ✅ **Smart Filtering**: Added custom vs system module distinction with automatic filtering
- ✅ **Dynamic Module Discovery**: Real-time detection of available modules from the modules directory
- ✅ **Robust Path Resolution**: Enhanced variable resolution for module paths
- ✅ **Improved Error Handling**: Better validation and error reporting
- ✅ **Comprehensive Testing**: Validated against multiple real-world scripts

## Requirements

- PowerShell 5.1 or later
- Read access to the script file being validated
- Optional: Access to module directories for dependency checking

## Installation

1. Place `Test-PowerShellSyntax.ps1` in your modules directory
2. Ensure execution policy allows script execution: `Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser`
3. Run the script with appropriate parameters

## Best Practices

1. **Use -Detailed for Development**: Get comprehensive information during script development
2. **Quick Checks for CI/CD**: Use -Quick for fast syntax validation in automated pipelines
3. **Module Organization**: Keep custom modules in a dedicated modules directory for automatic detection
4. **Regular Validation**: Run validation checks before committing PowerShell scripts to version control

## Exit Codes

- `0`: All validation checks passed
- `1`: Syntax errors found or validation failed

## Related Tools

This tool complements other PowerShell development tools:

- PSScriptAnalyzer for advanced static analysis
- Pester for unit testing
- PowerShell ISE/VS Code for development
