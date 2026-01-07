<#
.\eqgame-wrapper.ps1
Launches Quarm eqgame.exe and applies working set min/max limits.

.\quarm-eqgame-wrapper.ps1 -MinMB 256 -MaxMB 768 -ReapplySeconds 10
Launches Quarm eqgame.exe with a working set between 256MB and 768MB, reapplying every 10 seconds.

Notes:
- Working set limits are not a perfect "hard cap" on total memory; they mostly influence resident RAM.
- Elevation is typically required to open another process with SetQuota and to set working set limits.
#>

[CmdletBinding()]
param(
  [string]$Path = "C:\Games\Quarm\eqgame.exe",
  [string]$Args = "",
  [ValidateRange(16, 32768)]
  [int]$MinMB = 300,
  [ValidateRange(16, 32768)]
  [int]$MaxMB = 700,
  [ValidateRange(0, 3600)]
  [int]$ReapplySeconds = 15,
  [switch]$NoWait
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# --- Self-elevate early (before we launch EQ / call Add-Type) ---
$identity  = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
$adminRole = [Security.Principal.WindowsBuiltInRole]::Administrator

if (-not $principal.IsInRole($adminRole)) {
  Write-Host "Re-launching as Administrator..."
  $argList = @(
    "-NoProfile",
    "-ExecutionPolicy", "Bypass",
    "-File", "`"$PSCommandPath`""
  ) + $MyInvocation.UnboundArguments

  Start-Process -FilePath "powershell.exe" -Verb RunAs -ArgumentList $argList
  exit
}

if (-not (Test-Path -LiteralPath $Path)) { throw "Not found: $Path" }
if ($MinMB -ge $MaxMB) { throw "MinMB ($MinMB) must be less than MaxMB ($MaxMB)." }

# --- Add Win32 interop once per session ---
if (-not ("Win32" -as [type])) {
  Add-Type -Language CSharp -TypeDefinition @"
using System;
using System.Runtime.InteropServices;

public static class Win32
{
    [Flags]
    public enum ProcessAccessFlags : uint
    {
        QueryInformation = 0x0400,
        SetQuota         = 0x0100
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr OpenProcess(ProcessAccessFlags access, bool inheritHandle, int processId);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool CloseHandle(IntPtr hObject);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool SetProcessWorkingSetSizeEx(
        IntPtr hProcess,
        IntPtr dwMinimumWorkingSetSize,
        IntPtr dwMaximumWorkingSetSize,
        uint flags
    );

    public const uint QUOTA_LIMITS_HARDWS_MIN_ENABLE = 0x00000001;
    public const uint QUOTA_LIMITS_HARDWS_MAX_ENABLE = 0x00000002;

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern bool LookupPrivilegeValue(string lpSystemName, string lpName, out LUID lpLuid);

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool AdjustTokenPrivileges(IntPtr TokenHandle, bool DisableAllPrivileges,
        ref TOKEN_PRIVILEGES NewState, uint BufferLength, IntPtr PreviousState, IntPtr ReturnLength);

    [StructLayout(LayoutKind.Sequential)]
    public struct LUID { public uint LowPart; public int HighPart; }

    [StructLayout(LayoutKind.Sequential)]
    public struct LUID_AND_ATTRIBUTES { public LUID Luid; public uint Attributes; }

    [StructLayout(LayoutKind.Sequential)]
    public struct TOKEN_PRIVILEGES { public uint PrivilegeCount; public LUID_AND_ATTRIBUTES Privileges; }

    public const uint TOKEN_ADJUST_PRIVILEGES = 0x0020;
    public const uint TOKEN_QUERY = 0x0008;
    public const uint SE_PRIVILEGE_ENABLED = 0x0002;

    public static void EnablePrivilege(string privilegeName)
    {
        IntPtr token;
        if (!OpenProcessToken(System.Diagnostics.Process.GetCurrentProcess().Handle, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, out token))
            throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error(), "OpenProcessToken failed");

        try
        {
            LUID luid;
            if (!LookupPrivilegeValue(null, privilegeName, out luid))
                throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error(), "LookupPrivilegeValue failed");

            TOKEN_PRIVILEGES tp = new TOKEN_PRIVILEGES();
            tp.PrivilegeCount = 1;
            tp.Privileges = new LUID_AND_ATTRIBUTES();
            tp.Privileges.Luid = luid;
            tp.Privileges.Attributes = SE_PRIVILEGE_ENABLED;

            AdjustTokenPrivileges(token, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero);
            int err = Marshal.GetLastWin32Error();
            if (err != 0)
                throw new System.ComponentModel.Win32Exception(err, "AdjustTokenPrivileges failed");
        }
        finally
        {
            CloseHandle(token);
        }
    }
}
"@
}

function Set-WorkingSetMB {
  param(
    [Parameter(Mandatory)][System.Diagnostics.Process]$Process,
    [Parameter(Mandatory)][int]$MinMB,
    [Parameter(Mandatory)][int]$MaxMB
  )

  $minBytes = [IntPtr]([int64]$MinMB * 1MB)
  $maxBytes = [IntPtr]([int64]$MaxMB * 1MB)

  $hProc = [Win32]::OpenProcess(
    [Win32+ProcessAccessFlags]::QueryInformation -bor [Win32+ProcessAccessFlags]::SetQuota,
    $false,
    $Process.Id
  )

  if ($hProc -eq [IntPtr]::Zero) {
    $code = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
    Write-Warning "OpenProcess failed for PID $($Process.Id). Win32Error=$code (Access Denied is common if not elevated)."
    return
  }

  try {
    $flags = [Win32]::QUOTA_LIMITS_HARDWS_MIN_ENABLE -bor [Win32]::QUOTA_LIMITS_HARDWS_MAX_ENABLE
    $ok = [Win32]::SetProcessWorkingSetSizeEx($hProc, $minBytes, $maxBytes, $flags)
    if (-not $ok) {
      $code = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
      Write-Warning "SetProcessWorkingSetSizeEx failed for PID $($Process.Id). Win32Error=$code"
      return
    }
  }
  finally {
    [void][Win32]::CloseHandle($hProc)
  }
}

# Enable privilege (best-effort)
try { [Win32]::EnablePrivilege("SeIncreaseWorkingSetPrivilege") }
catch { Write-Warning "Could not enable SeIncreaseWorkingSetPrivilege (continuing): $($_.Exception.Message)" }

# --- Launch EQ WITHOUT ShellExecute (prevents redirection to Daybreak installer) ---
Write-Host "Launching EQ directly (no shell): $Path $Args"
$psi = [System.Diagnostics.ProcessStartInfo]::new()
$psi.FileName = $Path
$psi.WorkingDirectory = Split-Path -Path $Path
$psi.UseShellExecute = $false
if ($Args -and $Args.Trim().Length -gt 0) { $psi.Arguments = $Args }

$proc = [System.Diagnostics.Process]::Start($psi)
Write-Host "Launched PID $($proc.Id)"

# Apply once + verify actual image path (best-effort)
try {
  $proc.Refresh()
  Write-Host "Actual EXE: $($proc.MainModule.FileName)"
} catch {
  Write-Warning "Couldn't read MainModule.FileName."
}

$apply = {
  param($p, $min, $max)
  $p.Refresh()
  Set-WorkingSetMB -Process $p -MinMB $min -MaxMB $max
  $wsNow = [Math]::Round(($p.WorkingSet64 / 1MB), 1)
  Write-Host "Applied working set: Min=${min}MB Max=${max}MB (current ~${wsNow}MB)"
}

& $apply $proc $MinMB $MaxMB

if ($NoWait) { return }

if ($ReapplySeconds -gt 0) {
  Write-Host "Reapplying every $ReapplySeconds seconds. Ctrl+C to stop."
  while (-not $proc.HasExited) {
    Start-Sleep -Seconds $ReapplySeconds
    try { & $apply $proc $MinMB $MaxMB }
    catch {
      if ($proc.HasExited) { break }
      Write-Warning "Reapply failed: $($_.Exception.Message)"
    }
  }
} else {
  try { $proc.WaitForExit() } catch {}
}

Write-Host "EverQuest exited."
