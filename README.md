# QuarmWrapper

Largely made with thinking machines to help me run the `eqgame.exe` on my machine. 

I recommend running this in an elevated PowerShell window. The script should launch such an elevated terminal, if in a normal command prompt, but that doesn't seem to be happening at this current time.

## Commands

Examples of how to run the script.

Launches Quarm eqgame.exe and applies working set min/max limits.
```powershell
.\eqgame-wrapper.ps1
```

Launches Quarm eqgame.exe with a specified path.
```powershell
.\eqgame-wrapper.ps1 -EqDir "C:\Games\Quarm"
```

Launches Quarm eqgame.exe with a working set between 256MB and 768MB, reapplying every 10 seconds.
```powershell
.\eqgame-wrapper.ps1 -MinMB 256 -MaxMB 768 -ReapplySeconds 10
```

Launches Quarm eqgame.exe, defining the path, and with a working set between 256MB and 768MB, reapplying every 10 seconds.
```powershell
.\eqgame-wrapper.ps1 -EqDir "C:\Games\Quarm" -MinMB 256 -MaxMB 768 -ReapplySeconds 10
```

## Notes
- Working set limits are not a perfect "hard cap" on total memory; they mostly influence resident RAM.
- Elevation is typically required to open another process with SetQuota and to set working set limits.
