<#
.\quarm-wrapper.ps1
Launches Quarm eqgame.exe and applies working set min/max limits.

Notes:
- Working set limits are not a perfect "hard cap" on total memory; they mostly influence resident RAM.
- Elevation is typically required to open another process with SetQuota and to set working set limits.
#>

[CmdletBinding()]
param(
  # Option A: Full path to eqgame.exe
  [string]$Path = "C:\Games\Quarm\eqgame.exe",

  # Option B: Directory that contains eqgame.exe
  [string]$EqDir,

  # How long to wait after launching EQ before applying working set limits (helps during login/server/world handoff)
  [ValidateRange(0, 3600)]
  [int]$InitialDelaySeconds = 45,

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

# --- Self-elevate early ---
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

# --- Resolve eqgame.exe path ---
$ResolvedEqPath =
  if ($EqDir) { Join-Path -Path $EqDir -ChildPath "eqgame.exe" }
  else { $Path }

if (-not (Test-Path -LiteralPath $ResolvedEqPath)) {
  throw "eqgame.exe not found at: $ResolvedEqPath"
}

$ResolvedEqPath = (Resolve-Path -LiteralPath $ResolvedEqPath).Path

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

# Best-effort privilege
try { [Win32]::EnablePrivilege("SeIncreaseWorkingSetPrivilege") }
catch { Write-Warning "Could not enable SeIncreaseWorkingSetPrivilege (continuing): $($_.Exception.Message)" }

function Get-QuarmEqProcess {
  param([Parameter(Mandatory)][string]$ExePath)

  # Find eqgame.exe processes and pick the most recently started that matches our exact path.
  $escaped = $ExePath.Replace('\', '\\')
  $cim = Get-CimInstance Win32_Process -Filter "Name='eqgame.exe'" |
         Where-Object { $_.ExecutablePath -eq $ExePath }

  if (-not $cim) { return $null }

  $newest = $cim | Sort-Object CreationDate -Descending | Select-Object -First 1
  try { return Get-Process -Id $newest.ProcessId -ErrorAction Stop }
  catch { return $null }
}

function Set-WorkingSetMB {
  param(
    [Parameter(Mandatory)][System.Diagnostics.Process]$Process,
    [Parameter(Mandatory)][int]$MinMB,
    [Parameter(Mandatory)][int]$MaxMB
  )

  $Process.Refresh()
  if ($Process.HasExited) { return $false }

  $minBytes = [IntPtr]([int64]$MinMB * 1MB)
  $maxBytes = [IntPtr]([int64]$MaxMB * 1MB)

  $hProc = [Win32]::OpenProcess(
    [Win32+ProcessAccessFlags]::QueryInformation -bor [Win32+ProcessAccessFlags]::SetQuota,
    $false,
    $Process.Id
  )

  if ($hProc -eq [IntPtr]::Zero) {
    # If it exited between refresh and OpenProcess, don't treat as scary
    $Process.Refresh()
    if ($Process.HasExited) { return $false }

    $code = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
    Write-Warning "OpenProcess failed for PID $($Process.Id). Win32Error=$code"
    return $false
  }

  try {
    # flags = 0 for compatibility
    $ok = [Win32]::SetProcessWorkingSetSizeEx($hProc, $minBytes, $maxBytes, 0)
    if (-not $ok) {
      $Process.Refresh()
      if ($Process.HasExited) { return $false }

      $code = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
      Write-Warning "SetProcessWorkingSetSizeEx failed for PID $($Process.Id). Win32Error=$code"
      return $false
    }

    return $true
  }
  finally {
    [void][Win32]::CloseHandle($hProc)
  }
}

# --- Launch EQ (no shell) ---
Write-Host "Launching EQ directly (no shell): $ResolvedEqPath $Args"
$psi = [System.Diagnostics.ProcessStartInfo]::new()
$psi.FileName = $ResolvedEqPath
$psi.WorkingDirectory = Split-Path -Path $ResolvedEqPath
$psi.UseShellExecute = $false
if ($Args -and $Args.Trim().Length -gt 0) { $psi.Arguments = $Args }

$proc = [System.Diagnostics.Process]::Start($psi)
Write-Host "Launched PID $($proc.Id)"

try {
  $proc.Refresh()
  Write-Host "Actual EXE: $($proc.MainModule.FileName)"
} catch {
  Write-Warning "Couldn't read MainModule.FileName."
}

if ($InitialDelaySeconds -gt 0) {
  Write-Host "Waiting $InitialDelaySeconds seconds before applying working set limits..."
  Start-Sleep -Seconds $InitialDelaySeconds
}

$apply = {
  param([ref]$pRef, $min, $max, $exePath)

  # Follow process if it swapped during world-load
  $p = $pRef.Value
  if ($null -eq $p -or $p.HasExited) {
    $found = Get-QuarmEqProcess -ExePath $exePath
    if ($found) {
      $pRef.Value = $found
      $p = $found
      Write-Host "Switched to new eqgame.exe PID $($p.Id)"
    } else {
      Write-Host "No matching eqgame.exe process found (yet)."
      return
    }
  }

  $ok = Set-WorkingSetMB -Process $p -MinMB $min -MaxMB $max
  $p.Refresh()
  $wsNow = if ($p.HasExited) { 0 } else { [Math]::Round(($p.WorkingSet64 / 1MB), 1) }

  if ($ok) {
    Write-Host "Applied working set: Min=${min}MB Max=${max}MB (PID $($p.Id), current ~${wsNow}MB)"
  } else {
    Write-Host "Working set not applied (PID $($p.Id), current ~${wsNow}MB)"
  }
}

# First apply
$procRef = [ref]$proc
& $apply $procRef $MinMB $MaxMB $ResolvedEqPath

if ($NoWait) { return }

if ($ReapplySeconds -gt 0) {
  Write-Host "Reapplying every $ReapplySeconds seconds. Ctrl+C to stop."
  while ($true) {
    Start-Sleep -Seconds $ReapplySeconds

    # If we can't find ANY matching eqgame.exe anymore, we assume the game is done.
    $current = $procRef.Value
    $stillRunning =
      ($current -and -not $current.HasExited) -or (Get-QuarmEqProcess -ExePath $ResolvedEqPath)

    if (-not $stillRunning) { break }

    try { & $apply $procRef $MinMB $MaxMB $ResolvedEqPath }
    catch { Write-Warning "Reapply failed: $($_.Exception.Message)" }
  }
} else {
  try { $procRef.Value.WaitForExit() } catch {}
}

Write-Host "EverQuest exited."
