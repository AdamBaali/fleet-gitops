$CmdId = [System.DateTimeOffset]::UtcNow.ToUnixTimeSeconds()

Write-Host "Current Date and Time (UTC - YYYY-MM-DD HH:MM:SS formatted): $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Write-Host "Fleet URL: $env:FLEET_DESKTOP_FLEET_URL"

Write-Host "Triggering SCEP enrollment..."

# Create the SyncML command
$SyncML = "<Exec><CmdID>$CmdId</CmdID><Item><Target><LocURI>./Device/Vendor/MSFT/ClientCertificateInstall/SCEP/OktaVerify-Fleet/Install/Enroll</LocURI></Target></Item></Exec>"

# Base64 encode the command
$EncodedCommand = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($SyncML))

try {
    $Body = @{
        command = $EncodedCommand
        host_uuids = @("$FLEET_VAR_HOST_UUID")
    } | ConvertTo-Json

    $Response = Invoke-RestMethod -Uri "$env:FLEET_DESKTOP_FLEET_URL/api/v1/fleet/commands/run" -Method POST -Headers @{"Authorization"="Bearer $FLEET_SECRET_API";"Content-Type"="application/json"} -Body $Body
    Write-Host "PASS - Command UUID: $($Response.command_uuid)"
}
catch {
    Write-Host "FAIL - SCEP enrollment failed"
}