# SanitialX Windows Agent

The Windows agent is a native PowerShell endpoint client. It uses the same SanitialX enrollment, heartbeat, software inventory, event batching, and offline-detection APIs as the Linux agent, without requiring Python on the endpoint.

## Requirements

- Windows 10/11 or Windows Server with Windows PowerShell 5.1+
- Run enrollment and continuous monitoring as Administrator/SYSTEM
- Security Event Log access enabled
- Network access to the SanitialX backend

## 1. Install

Open an elevated PowerShell prompt:

```powershell
New-Item -ItemType Directory -Force 'C:\Program Files\SanitialX' | Out-Null
Copy-Item .\SanitialX-Agent.ps1 'C:\Program Files\SanitialX\SanitialX-Agent.ps1'
```

## 2. Enroll

The bootstrap enrollment key is used only to obtain a unique per-endpoint token.

```powershell
$env:SANITIALX_SERVER_URL = 'http://SERVER:8000/api/v1'
$env:SANITIALX_ENROLLMENT_KEY = '<enrollment-key>'
& 'C:\Program Files\SanitialX\SanitialX-Agent.ps1' -Command Enroll
Remove-Item Env:SANITIALX_ENROLLMENT_KEY
```

Endpoint state is stored under `%ProgramData%\SanitialX`. Credential/state files are ACL-restricted to SYSTEM and local Administrators.

## 3. Test manually

```powershell
& 'C:\Program Files\SanitialX\SanitialX-Agent.ps1' -Command Heartbeat
& 'C:\Program Files\SanitialX\SanitialX-Agent.ps1' -Command Inventory
& 'C:\Program Files\SanitialX\SanitialX-Agent.ps1' -Command Collect
& 'C:\Program Files\SanitialX\SanitialX-Agent.ps1' -Command Flush
```

## 4. Security collectors

The agent is passive/read-only. It currently collects:

- Security Event ID `4625` → `WINDOWS_LOGON_FAILURE`
- Security Event ID `4624` → `WINDOWS_LOGON_SUCCESS`
- System log Critical/Error/Warning → `WINDOWS_SYSTEM_ALERT`

For Security events it extracts fields such as remote IP, target username, and logon type when Windows supplies them. Record-ID cursors prevent normal polling from repeatedly replaying the same events. On first run the cursor starts at the newest existing record, so historical logs are not bulk-forwarded unexpectedly.

## 5. Run automatically at startup

Create a SYSTEM scheduled task from an elevated PowerShell prompt:

```powershell
$script = 'C:\Program Files\SanitialX\SanitialX-Agent.ps1'
$server = 'http://SERVER:8000/api/v1'
$action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$script`" -Server `"$server`" -Command Run"
$trigger = New-ScheduledTaskTrigger -AtStartup
$principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
Register-ScheduledTask -TaskName 'SanitialX Agent' -Action $action -Trigger $trigger -Principal $principal -Force
Start-ScheduledTask -TaskName 'SanitialX Agent'
```

## Security notes

- Use HTTPS outside a trusted development network.
- Do not persist the bootstrap enrollment key after enrollment.
- Re-enrollment rotates the endpoint token.
- Event forwarding uses a durable local JSONL spool and retries after connection failures.
- The current agent only reads telemetry; response/remediation actions are intentionally reserved for the later approval-based SOAR module.
