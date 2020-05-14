#Must exist at the header of every single executable script!
Set-Location $args[1]
. .\__config.ps1 

function Remove-AndRecon
{
    Get-ChildItem -Path "C:\" -Include $global:BadPrograms -Recurse | Remove-Item -Force
    # New-Item -Path ".\Checklist\FILES TO SEARCH.txt" -Force
    <#
        foreach ($line in $(Get-Content -Path .\Data\mimes.csv))
        {
            $parts = $($line -split ",");
            $ext = $parts[0];
            $Content = $(Get-ChildItem -Path "C:\" -Include $ext -Recurse | Format-List);
            Add-Content -Path ".\Checklist\FILES TO SEARCH.txt" -Force -Value $Content
        }
    #>
    
}

try { Remove-AndRecon; } catch { Write-Error $_; }