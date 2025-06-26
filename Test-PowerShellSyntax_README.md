# How to Use Test-PowerShellSyntax.ps1

```markdown
# Test-PowerShellSyntax Usage Examples

powershell -File "C:\Users\dcasey\Documents\Programming\Powershell\modules\Test-PowerShellSyntax.ps1" -ScriptPath "C:\Scripts\MyScript.ps1" -Quick

# Full validation with module dependency checking

powershell -File "C:\Users\dcasey\Documents\Programming\Powershell\modules\Test-PowerShellSyntax.ps1" -ScriptPath "C:\Scripts\MyScript.ps1" -ModulePath "C:\Modules"

## Full validation with module dependency checking

powershell -File "C:\Users\dcasey\Documents\Programming\Powershell\modules\Test-PowerShellSyntax.ps1" -ScriptPath "C:\Scripts\MyScript.ps1" -ModulePath "C:\Modules"

## Detailed analysis with comprehensive output

# Check the Install-SamClient.ps1 script

powershell -File "C:\Users\dcasey\Documents\Programming\Powershell\modules\Test-PowerShellSyntax.ps1" -ScriptPath "C:\Users\dcasey\Documents\Programming\Powershell\WCL\PublicPCs\scripts\Install-SamClient.ps1" -ModulePath "C:\Users\dcasey\Documents\Programming\Powershell\modules"

## Check the Install-SamClient.ps1 script

powershell -File "C:\Users\dcasey\Documents\Programming\Powershell\modules\Test-PowerShellSyntax.ps1" -ScriptPath "C:\Users\dcasey\Documents\Programming\Powershell\WCL\PublicPCs\scripts\Install-SamClient.ps1" -ModulePath "C:\Users\dcasey\Documents\Programming\Powershell\modules"
```
