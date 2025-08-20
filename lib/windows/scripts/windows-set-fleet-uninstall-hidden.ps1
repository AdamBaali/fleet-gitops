# Harden the uninstall experience for Fleet osquery on Windows without relying on ProductCode GUIDs.
Sets ARP flags to remove or disable uninstall and change options in Apps and Features.

What it does
1. Searches both 64-bit and 32-bit uninstall registry hives.
2. Finds any entry where DisplayName matches Fleet osquery.
3. Sets NoRemove, NoModify, and NoRepair to 1.
4. Optionally sets SystemComponent to 1 to hide the entry completely.

Notes
This changes UI behavior only. It does not stop an administrator from running an uninstall command manually.
#>

# Set to $true if you want to hide the entry entirely in Apps and Features
$HideCompletely = $false

# Registry roots to search
$UninstallRoots = @(
  'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',
  'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall'
)

# Collect matching uninstall entries by DisplayName
$Matches = foreach ($root in $UninstallRoots) {
  # Skip root if it does not exist on this host
  if (-not (Test-Path $root)) { continue }

  # Enumerate subkeys under the uninstall root
  Get-ChildItem $root -ErrorAction SilentlyContinue | ForEach-Object {
    try {
      # Read properties from the uninstall entry
      $props = Get-ItemProperty -Path $_.PSPath -ErrorAction Stop

      # Select entries where DisplayName starts with Fleet osquery
      if ($props.PSObject.Properties.Name -contains 'DisplayName' -and $props.DisplayName -like 'Fleet osquery*') {
        # Return a simple object with the key path and display name
        [pscustomobject]@{
          KeyPath     = $_.PSPath
          DisplayName = $props.DisplayName
        }
      }
    } catch {
      # Ignore keys we cannot read
    }
  }
}

# Exit quietly if no Fleet osquery entry was found
if (-not $Matches -or $Matches.Count -eq 0) {
  Write-Host 'Fleet osquery not found in uninstall registry.'
  return
}

# For each matching uninstall entry set the ARP flags
foreach ($m in $Matches) {

  # Set NoRemove to hide or disable the Uninstall button
  New-ItemProperty -Path $m.KeyPath -Name 'NoRemove' -PropertyType DWord -Value 1 -Force | Out-Null

  # Set NoModify to hide or disable the Change button
  New-ItemProperty -Path $m.KeyPath -Name 'NoModify' -PropertyType DWord -Value 1 -Force | Out-Null

  # Set NoRepair to hide repair options if present
  New-ItemProperty -Path $m.KeyPath -Name 'NoRepair' -PropertyType DWord -Value 1 -Force | Out-Null

  # Optional hide the entire entry from Apps and Features
  if ($HideCompletely) {
    New-ItemProperty -Path $m.KeyPath -Name 'SystemComponent' -PropertyType DWord -Value 1 -Force | Out-Null
  }

  # Read back values to confirm and print a concise summary
  $vals = Get-ItemProperty -Path $m.KeyPath -Name NoRemove,NoModify,NoRepair,SystemComponent -ErrorAction SilentlyContinue
  Write-Host "Hardened: $($m.DisplayName)"
  Write-Host "Key: $($m.KeyPath)"
  Write-Host ("Flags NoRemove={0} NoModify={1} NoRepair={2} SystemComponent={3}" -f `
    $vals.NoRemove, $vals.NoModify, $vals.NoRepair, $vals.SystemComponent)
}
