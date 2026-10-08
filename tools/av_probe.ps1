$ErrorActionPreference = 'SilentlyContinue'
[Console]::OutputEncoding = [Text.Encoding]::UTF8

Write-Output "== Defender status =="
$cs = Get-MpComputerStatus
if ($null -eq $cs) {
    Write-Output "Get-MpComputerStatus: no result (standard user cannot read it)"
} else {
    Write-Output ("AVProductStates  : " + ($cs.AVSecurityCenterState))
    Write-Output ("RealTimeProtection : " + $cs.RealTimeProtectionEnabled)
    Write-Output ("RtpEnabled         : " + $cs.RtpEnabled)
    Write-Output ("OnAccessProtection : " + $cs.OnAccessProtectionEnabled)
    Write-Output ("QuickScanAge(days) : " + $cs.QuickScanAge)
    Write-Output ("AMServiceVersion   : " + $cs.AMEngineVersion)
}

Write-Output "== Defender detections in the last 24 h mentioning our build =="
$d = Get-MpThreatDetection | Where-Object { $_.InitialDetectionTime -gt (Get-Date).AddHours(-24) }
if ($null -eq $d) {
    Write-Output "none returned"
} else {
    Write-Output ("total detections: " + @($d).Count)
    $ours = @($d | Where-Object { $_.Resources -match 'SysProbe' })
    Write-Output ("mentioning SysProbe: " + $ours.Count)
    foreach ($o in $ours) { Write-Output ("  threatid=" + $o.ThreatID + " path=" + ($o.Resources -join ';')) }
}

Write-Output "== Quarantine / threat history (name level) =="
$t = Get-MpThreat | Where-Object { $_.LastStatusTime -gt (Get-Date).AddDays(-2) }
if ($null -eq $t) { Write-Output "none" } else {
    Write-Output ("recent threats: " + @($t).Count)
    foreach ($x in $t) { Write-Output ("  " + $x.ThreatName + " | " + $x.ActiveAssets) }
}

Write-Output "== Kaspersky presence (status query needs elevation; not run) =="
$kdir = Get-ChildItem 'C:\Program Files (x86)\Kaspersky Lab' -Directory
foreach ($k in $kdir) { Write-Output ("  " + $k.Name) }

Write-Output "== Anything exe-shaped under dist still present =="
Get-ChildItem 'D:\XIAZ\Wiki\READ\black\SysProbe-Lite\dist' -Recurse -Filter '*.exe' |
    ForEach-Object { Write-Output ("  " + $_.Name + " " + $_.Length + " bytes, lastwrite " + $_.LastWriteTime.ToString('s')) }
