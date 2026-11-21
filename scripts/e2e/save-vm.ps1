$ErrorActionPreference = 'Stop'
'SAVE_START' | Out-File -FilePath 'D:\PerchSandbox\staging\save-vm.log' -Encoding ascii
Import-Module Hyper-V
Save-VM -Name 'PerchSandbox' -ErrorAction SilentlyContinue
Save-VM -Name 'PerchVPN-Sandbox'
Start-Sleep -Seconds 5
$vm = Get-VM -Name 'PerchVPN-Sandbox'
("STATE=" + $vm.State) | Out-File -FilePath 'D:\PerchSandbox\staging\save-vm.log' -Append -Encoding ascii
("MEM=" + $vm.MemoryAssigned) | Out-File -FilePath 'D:\PerchSandbox\staging\save-vm.log' -Append -Encoding ascii
'SAVE_DONE' | Out-File -FilePath 'D:\PerchSandbox\staging\save-vm.log' -Append -Encoding ascii
