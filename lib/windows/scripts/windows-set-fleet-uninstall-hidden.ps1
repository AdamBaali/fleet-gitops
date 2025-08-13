# Search for Fleet osquery and set NoRemove to 1
$product = Get-CimInstance Win32_Product | Where-Object { $_.Name -like "*Fleet osquery*" }

if ($product) {
    $productCode = $product.IdentifyingNumber
    $regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\$productCode"

    # Set NoRemove = 1
    New-ItemProperty -Path $regPath -Name "NoRemove" -PropertyType DWord -Value 1 -Force | Out-Null

    # Confirm and display result
    $value = Get-ItemProperty -Path $regPath -Name "NoRemove" -ErrorAction SilentlyContinue
    Write-Host "Fleet osquery found"
    Write-Host "ProductCode (GUID): $productCode"
    Write-Host "Registry Path: $regPath"
    Write-Host "NoRemove is now set to: $($value.NoRemove)"
} else {
    Write-Host "Fleet osquery not found on this system."
}