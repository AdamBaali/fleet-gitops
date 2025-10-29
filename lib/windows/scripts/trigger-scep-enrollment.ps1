# ----- USER SETTINGS -----
# FOR GUI USAGE:
# Add your secret (with FLEET_SECRET_ prefix) to Fleet Desktop's Controls > Variables
# Example: If you create a variable named "API", it becomes FLEET_SECRET_API
# Then update the variable name in the line below to match your Fleet secret name
# WARNING: Fleet will fail to upload this script if the variable name doesn't exist in your Fleet secrets
# FOR GITOPS USAGE: 
# Set the FLEET_API_TOKEN environment variable in your workflow before running this script

$NODE_NAME = "OKTA"                    
# Edit this to match your CSP node name

# Check if running in GitOps (GitHub Actions) context or Fleet GUI context
if ($env:FLEET_API_TOKEN) {
    # GitOps context - use environment variable set by GitHub Actions
    $FLEET_API = $env:FLEET_API_TOKEN
    Write-Host "Using GitOps API token from environment variable"
} elseif ($env:FLEET_SECRET_API) {
    # Fleet GUI context - use Fleet secret
    $FLEET_API = $env:FLEET_SECRET_API
    Write-Host "Using Fleet GUI secret"
} else {
    Write-Host "ERROR: No API token found. Please set either FLEET_API_TOKEN (GitOps) or FLEET_SECRET_API (GUI)"
    exit 1
}
# -------------------------

$CmdId = [System.DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
Write-Host "Current Date and Time (UTC - YYYY-MM-DD HH:MM:SS formatted): $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Write-Host "Fleet URL: $env:FLEET_DESKTOP_FLEET_URL"

try {
    $HostUUID = (Get-CimInstance Win32_ComputerSystemProduct).UUID
    Write-Host "Host UUID: $HostUUID"
} catch {
    $HostUUID = (Get-WmiObject Win32_ComputerSystemProduct).UUID
    Write-Host "Host UUID (via WMI): $HostUUID"
}

Write-Host "Command ID: $CmdId"
Write-Host "Triggering SCEP enrollment..."

$SyncML = @"
<Exec>
  <CmdID>$CmdId</CmdID>
  <Item>
    <Target>
      <LocURI>./Device/Vendor/MSFT/ClientCertificateInstall/SCEP/$NODE_NAME/Install/Enroll</LocURI>
    </Target>
    <Meta>
      <Format xmlns="syncml:metinf">null</Format>
      <Type>text/plain</Type>
    </Meta>
    <Data></Data>
  </Item>
</Exec>
"@

$EncodedCommand = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($SyncML))

$Body = @{
    command = $EncodedCommand
    host_uuids = @($HostUUID)
} | ConvertTo-Json

Write-Host "Sending MDM command to host: $HostUUID"

try {
    $Response = Invoke-RestMethod -Uri "$env:FLEET_DESKTOP_FLEET_URL/api/v1/fleet/commands/run" `
        -Method POST `
        -Headers @{"Authorization"="Bearer $FLEET_API";"Content-Type"="application/json"} `
        -Body $Body
    $CommandUUID = $Response.command_uuid
    Write-Host "PASS - SCEP enrollment command sent successfully!"
    Write-Host "Command UUID: $CommandUUID"
    Write-Host ""
    Write-Host "To check results, copy and paste this command:"
    Write-Host "fleetctl get mdm-command-results --id=$CommandUUID"
}
catch {
    Write-Host "FAIL - SCEP enrollment failed: $($_.Exception.Message)"
    if ($_.ErrorDetails) {
        Write-Host "Error Details: $($_.ErrorDetails.Message)"
    }
}
