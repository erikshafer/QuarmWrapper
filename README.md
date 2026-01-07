# QuarmWrapper

Largely made with thinking machines to help me run the `eqgame.exe` on my machine.

```powershell
eqgame-wrapper.ps1
```
Launches Quarm eqgame.exe and applies working set min/max limits.

```powershell
.\quarm-eqgame-wrapper.ps1 -EqDir "D:\Games\Quarm"
```
Launches Quarm eqgame.exe with a specified path.


```powershell
quarm-eqgame-wrapper.ps1 -MinMB 256 -MaxMB 768 -ReapplySeconds 10
```
Launches Quarm eqgame.exe with a working set between 256MB and 768MB, reapplying every 10 seconds.

```powershell
quarm-eqgame-wrapper.ps1 -EqDir "D:\Games\Quarm" -MinMB 256 -MaxMB 768 -ReapplySeconds 10
```
Launches Quarm eqgame.exe, defining the path, and with a working set between 256MB and 768MB, reapplying every 10 seconds.

## Notes:
- Working set limits are not a perfect "hard cap" on total memory; they mostly influence resident RAM.
- Elevation is typically required to open another process with SetQuota and to set working set limits.
