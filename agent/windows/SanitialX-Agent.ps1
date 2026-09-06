param(
    [Parameter(Mandatory=$false)]
    [ValidateSet('Enroll','Heartbeat','Inventory','Collect','Flush','Run','Event')]
    [string]$Command = 'Run',
    [string]$Server = $env:SANITIALX_SERVER_URL,
    [string]$EnrollmentKey = $env:SANITIALX_ENROLLMENT_KEY,
    [string]$EventType = 'WINDOWS_TEST',
    [ValidateSet('INFO','LOW','MEDIUM','HIGH','CRITICAL')]
    [string]$Severity = 'INFO',
    [string]$Message = 'SanitialX Windows agent test event'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$Script:Version = '0.1.0'
if ([string]::IsNullOrWhiteSpace($Server)) {
    $Server = 'http://127.0.0.1:8000/api/v1'
}
$Server = $Server.TrimEnd('/')
$Script:StateDir = Join-Path $env:ProgramData 'SanitialX'
$Script:TokenPath = Join-Path $Script:StateDir 'agent-token'
$Script:SpoolPath = Join-Path $Script:StateDir 'events.jsonl'
$Script:SecurityCursorPath = Join-Path $Script:StateDir 'security-record-id'
$Script:SystemCursorPath = Join-Path $Script:StateDir 'system-record-id'

function Ensure-StateDirectory {
    if (-not (Test-Path $Script:StateDir)) {
        New-Item -ItemType Directory -Path $Script:StateDir -Force | Out-Null
    }
}

function Protect-File([string]$Path) {
    if (Test-Path $Path) {
        & icacls.exe $Path /inheritance:r /grant:r '*S-1-5-18:F' '*S-1-5-32-544:F' | Out-Null
    }
}

function Write-SecureText([string]$Path, [string]$Value) {
    Ensure-StateDirectory
    $tmp = "$Path.tmp"
    [System.IO.File]::WriteAllText($tmp, $Value, [System.Text.UTF8Encoding]::new($false))
    Move-Item -Force $tmp $Path
    Protect-File $Path
}

function Get-AgentId {
    Ensure-StateDirectory
    $idPath = Join-Path $Script:StateDir 'agent-id'
    if (Test-Path $idPath) {
        return (Get-Content -Raw $idPath).Trim()
    }
    $machineGuid = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Cryptography' -Name MachineGuid).MachineGuid
    $id = "windows-$machineGuid"
    Write-SecureText $idPath "$id`n"
    return $id
}

function Get-AgentToken {
    if (-not (Test-Path $Script:TokenPath)) {
        throw 'Agent is not enrolled. Run Enroll first.'
    }
    return (Get-Content -Raw $Script:TokenPath).Trim()
}

function Invoke-SanitialXJson {
    param(
        [string]$Method,
        [string]$Url,
        [object]$Body = $null,
        [hashtable]$Headers = @{},
        [int]$TimeoutSec = 30
    )
    $params = @{
        Method = $Method
        Uri = $Url
        Headers = $Headers
        TimeoutSec = $TimeoutSec
        ErrorAction = 'Stop'
    }
    if ($null -ne $Body) {
        $params['ContentType'] = 'application/json'
        $params['Body'] = ($Body | ConvertTo-Json -Depth 12 -Compress)
    }
    return Invoke-RestMethod @params
}

function Get-PrimaryIPv4 {
    $address = Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
        Where-Object { $_.IPAddress -notlike '127.*' -and $_.AddressState -eq 'Preferred' } |
        Sort-Object InterfaceMetric |
        Select-Object -First 1 -ExpandProperty IPAddress
    if ([string]::IsNullOrWhiteSpace($address)) { return '127.0.0.1' }
    return $address
}

function Get-HeartbeatPayload {
    $cpu = Get-CimInstance Win32_Processor | Measure-Object -Property LoadPercentage -Average
    $os = Get-CimInstance Win32_OperatingSystem
    $total = [double]$os.TotalVisibleMemorySize
    $free = [double]$os.FreePhysicalMemory
    $memory = if ($total -gt 0) { [Math]::Round((($total - $free) / $total) * 100, 2) } else { 0 }
    return @{
        cpu_usage = [Math]::Round([double]($cpu.Average ?? 0), 2)
        memory_usage = $memory
        agent_version = $Script:Version
        ip_address = Get-PrimaryIPv4
    }
}

function Invoke-Enroll {
    if ([string]::IsNullOrWhiteSpace($EnrollmentKey)) {
        throw 'Enrollment key required via -EnrollmentKey or SANITIALX_ENROLLMENT_KEY.'
    }
    $os = Get-CimInstance Win32_OperatingSystem
    $payload = @{
        agent_id = Get-AgentId
        hostname = $env:COMPUTERNAME
        ip_address = Get-PrimaryIPv4
        os = "$($os.Caption) $($os.Version) ($env:PROCESSOR_ARCHITECTURE)"
        agent_version = $Script:Version
    }
    $result = Invoke-SanitialXJson -Method POST -Url "$Server/agents/enroll" -Body $payload -Headers @{'X-Enrollment-Key'=$EnrollmentKey}
    Write-SecureText $Script:TokenPath "$($result.agent_token)`n"
    return $result
}

function Invoke-Heartbeat {
    return Invoke-SanitialXJson -Method POST -Url "$Server/agents/$(Get-AgentId)/heartbeat" -Body (Get-HeartbeatPayload) -Headers @{'X-Agent-Token'=(Get-AgentToken)}
}

function Get-InstalledSoftware {
    $paths = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
    )
    $items = New-Object System.Collections.Generic.List[object]
    foreach ($path in $paths) {
        Get-ItemProperty $path -ErrorAction SilentlyContinue | ForEach-Object {
            if (-not [string]::IsNullOrWhiteSpace($_.DisplayName) -and -not [string]::IsNullOrWhiteSpace($_.DisplayVersion)) {
                $items.Add(@{
                    vendor = [string]($_.Publisher ?? '')
                    product = [string]$_.DisplayName
                    package_name = [string]$_.DisplayName
                    version = [string]$_.DisplayVersion
                    ecosystem = 'windows'
                    source = 'sanitialx-windows-agent'
                })
            }
        }
    }
    return @($items | Sort-Object { $_.product }, { $_.version } -Unique | Select-Object -First 5000)
}

function Invoke-Inventory {
    $payload = @{ software = @(Get-InstalledSoftware) }
    return Invoke-SanitialXJson -Method PUT -Url "$Server/agents/$(Get-AgentId)/inventory/software" -Body $payload -Headers @{'X-Agent-Token'=(Get-AgentToken)} -TimeoutSec 90
}

function Add-SpoolEvent {
    param(
        [string]$Type,
        [string]$Level,
        [string]$Text,
        [string]$SourceIp = $null,
        [hashtable]$Metadata = @{}
    )
    Ensure-StateDirectory
    $event = @{
        event_id = [guid]::NewGuid().ToString()
        event_type = $Type
        timestamp = [DateTime]::UtcNow.ToString('o')
        severity = $Level
        source_ip = $SourceIp
        destination_ip = Get-PrimaryIPv4
        message = if ($Text.Length -gt 4000) { $Text.Substring(0,4000) } else { $Text }
        metadata = @{ collector = 'sanitialx-windows-agent' }
    }
    foreach ($key in $Metadata.Keys) { $event.metadata[$key] = $Metadata[$key] }
    Add-Content -Path $Script:SpoolPath -Value ($event | ConvertTo-Json -Depth 10 -Compress) -Encoding UTF8
    Protect-File $Script:SpoolPath
}

function Get-EventDataMap([System.Diagnostics.Eventing.Reader.EventRecord]$Record) {
    $map = @{}
    try {
        [xml]$xml = $Record.ToXml()
        foreach ($node in $xml.Event.EventData.Data) {
            if ($node.Name) { $map[[string]$node.Name] = [string]$node.'#text' }
        }
    } catch {}
    return $map
}

function Initialize-Cursor([string]$Path, [string]$LogName) {
    if (Test-Path $Path) { return }
    $latest = Get-WinEvent -LogName $LogName -MaxEvents 1 -ErrorAction SilentlyContinue
    $recordId = if ($null -ne $latest) { [long]$latest.RecordId } else { 0 }
    Write-SecureText $Path "$recordId`n"
}

function Collect-SecurityEvents {
    Initialize-Cursor $Script:SecurityCursorPath 'Security'
    $cursor = [long]((Get-Content -Raw $Script:SecurityCursorPath).Trim())
    $records = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624,4625} -MaxEvents 500 -ErrorAction SilentlyContinue |
        Where-Object { $_.RecordId -gt $cursor } |
        Sort-Object RecordId
    $maxRecord = $cursor
    $queued = 0
    foreach ($record in $records) {
        $data = Get-EventDataMap $record
        $ip = [string]($data['IpAddress'] ?? '')
        if ($ip -eq '-' -or $ip -eq '::1') { $ip = $null }
        $user = [string]($data['TargetUserName'] ?? '')
        $logonType = [string]($data['LogonType'] ?? '')
        if ($record.Id -eq 4625) {
            Add-SpoolEvent -Type 'WINDOWS_LOGON_FAILURE' -Level 'MEDIUM' -Text $record.Message -SourceIp $ip -Metadata @{user=$user; logon_type=$logonType; event_id=4625; log_source='Security'}
        } else {
            Add-SpoolEvent -Type 'WINDOWS_LOGON_SUCCESS' -Level 'INFO' -Text $record.Message -SourceIp $ip -Metadata @{user=$user; logon_type=$logonType; event_id=4624; log_source='Security'}
        }
        if ($record.RecordId -gt $maxRecord) { $maxRecord = $record.RecordId }
        $queued++
    }
    if ($maxRecord -gt $cursor) { Write-SecureText $Script:SecurityCursorPath "$maxRecord`n" }
    return $queued
}

function Collect-SystemEvents {
    Initialize-Cursor $Script:SystemCursorPath 'System'
    $cursor = [long]((Get-Content -Raw $Script:SystemCursorPath).Trim())
    $records = Get-WinEvent -FilterHashtable @{LogName='System'; Level=1,2,3} -MaxEvents 300 -ErrorAction SilentlyContinue |
        Where-Object { $_.RecordId -gt $cursor } |
        Sort-Object RecordId
    $maxRecord = $cursor
    $queued = 0
    foreach ($record in $records) {
        $level = if ($record.Level -eq 1) { 'CRITICAL' } elseif ($record.Level -eq 2) { 'HIGH' } else { 'MEDIUM' }
        Add-SpoolEvent -Type 'WINDOWS_SYSTEM_ALERT' -Level $level -Text $record.Message -Metadata @{provider=$record.ProviderName; windows_event_id=$record.Id; log_source='System'}
        if ($record.RecordId -gt $maxRecord) { $maxRecord = $record.RecordId }
        $queued++
    }
    if ($maxRecord -gt $cursor) { Write-SecureText $Script:SystemCursorPath "$maxRecord`n" }
    return $queued
}

function Invoke-Collect {
    return (Collect-SecurityEvents) + (Collect-SystemEvents)
}

function Invoke-Flush([int]$BatchSize = 200) {
    if (-not (Test-Path $Script:SpoolPath)) { return 0 }
    $lines = @(Get-Content $Script:SpoolPath | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    if ($lines.Count -eq 0) { return 0 }
    $take = [Math]::Min([Math]::Max($BatchSize,1), [Math]::Min(500,$lines.Count))
    $events = @()
    for ($i=0; $i -lt $take; $i++) { $events += ($lines[$i] | ConvertFrom-Json) }
    Invoke-SanitialXJson -Method POST -Url "$Server/agents/$(Get-AgentId)/events" -Body @{events=$events} -Headers @{'X-Agent-Token'=(Get-AgentToken)} | Out-Null
    $remaining = if ($take -lt $lines.Count) { @($lines[$take..($lines.Count-1)]) } else { @() }
    Write-SecureText $Script:SpoolPath ($(if ($remaining.Count) { ($remaining -join "`n") + "`n" } else { '' }))
    return $take
}

function Invoke-AgentRun {
    $nextInventory = [DateTime]::UtcNow
    $retry = 5
    while ($true) {
        try {
            Invoke-Collect | Out-Null
            Invoke-Flush | Out-Null
            Invoke-Heartbeat | Out-Null
            if ([DateTime]::UtcNow -ge $nextInventory) {
                Invoke-Inventory | Out-Null
                $nextInventory = [DateTime]::UtcNow.AddHours(6)
            }
            $retry = 5
            Start-Sleep -Seconds 30
        } catch {
            Write-Error "SanitialX agent cycle failed: $($_.Exception.Message)"
            Start-Sleep -Seconds $retry
            $retry = [Math]::Min($retry * 2, 300)
        }
    }
}

Ensure-StateDirectory
switch ($Command) {
    'Enroll' { Invoke-Enroll | ConvertTo-Json -Depth 10 }
    'Heartbeat' { Invoke-Heartbeat | ConvertTo-Json -Depth 10 }
    'Inventory' { Invoke-Inventory | ConvertTo-Json -Depth 10 }
    'Collect' { @{queued=(Invoke-Collect)} | ConvertTo-Json }
    'Flush' { @{forwarded=(Invoke-Flush)} | ConvertTo-Json }
    'Event' { Add-SpoolEvent -Type $EventType -Level $Severity -Text $Message; 'queued' }
    'Run' { Invoke-AgentRun }
}
