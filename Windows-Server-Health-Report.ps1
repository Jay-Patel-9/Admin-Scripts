################################################################################# 
## 
## Windows Health Checkup Script
## This script checks for:
## 1. OS version & info 
## 2. CPU Usage
## 3. Diskspace check for C: Drive via function arugment. Just change drive letter where you're calling a function.
## 4. Top 5 CPU using application.
## 5. Top 5 Memory using application. 
## 6. Top 5 orphaned process sorted by CPU usage
##
## It has two commented lines which converts command output to comma separated output.
##
###############################################################################

function Get-CPUAverage{
    Get-WmiObject win32_processor | Measure-Object -property LoadPercentage -Average | Select-Object Average
}
function Get-MemoryUsage {
    Get-WmiObject -Class win32_operatingsystem | Select-Object @{Name = "MemoryUsage"; Expression = { ((($_.TotalVisibleMemorySize - $_.FreePhysicalMemory)*100)/ $_.TotalVisibleMemorySize) }}
}
function Get-DiskSpace($drv){
    Get-WmiObject -Class win32_Volume  -Filter "DriveLetter = '$drv'" |
    Select-object @{Name = "$drv Drive Total Usage"; Expression = { ((($_.Capacity - $_.FreeSpace ) / $_.Capacity)*100) } }
}
function Get-TopCPUProcess{
    Get-WmiObject Win32_PerfFormattedData_PerfProc_Process | `where-object{ $_.Name -ne "_Total" -and $_.Name -ne "Idle"}  | Select-Object -First 5 | select-object "Name" | select-object -expandproperty Name
    #Uncomment following line to get comma separated $cpuproc output but before that store above commandoutput to $cpuproc
    # $topproc=(($cpuproc -split '\r?\n').Trim() | ForEach-Object { '"'+$_+'"' }) -Join ','
}
function Get-TopMemoryProcess {
    Get-Process | Sort-Object -Descending WS | Select-Object -first 5 | Select-Object -ExpandProperty ProcessName
    #Uncomment following line to get comma separated $memproc output but before that store above commandoutput to $memproc
    # $topmemproc=(($memproc -split '\r?\n').Trim() | ForEach-Object { '"'+$_+'"' }) -Join ','
}
#Following function 
function Get-OrphanedProcesses {
    $procsWithParent = Get-CimInstance -ClassName "win32_process" | Select-Object ProcessId,ParentProcessId
    $orphaned = $procsWithParent | Where-Object -Property ParentProcessId -NotIn $procsWithParent.ProcessId
    Get-Process | Where-Object -Property Id -In $orphaned.ProcessId | Sort-Object -Descending CPU |Select-Object -first 5 | Format-Table ProcessName,Id, WS, CPU 
  }

Write-Output "--------------------------------------"
Write-Output "[#] OS & Version Info"
Write-Output "--------------------------------------"
Get-WmiObject -Class win32_operatingsystem
Write-Output "--------------------------------------"
Write-Output "[#] CPU Average Usage"
Write-Output "--------------------------------------"
Get-CPUAverage
Write-Output "--------------------------------------"
Write-Output "[#] Memory Usage"
Write-Output "--------------------------------------"
Get-MemoryUsage
Write-Output "--------------------------------------"
Write-Output "[#] Diskspace Usage"
Write-Output "--------------------------------------"
Get-DiskSpace C:
Write-Output "--------------------------------------"
Write-Output "[#] Top 5 CPU consuming application"
Write-Output "--------------------------------------"
Get-TopCPUProcess
Write-Output ""
Write-Output "--------------------------------------"
Write-Output "[#] Top 5 Memory consumption applications"
Write-Output "--------------------------------------"
Get-TopMemoryProcess
Write-Output ""
Write-Output "--------------------------------------"
Write-Output "[#] Top 5 CPU eating zombie processes"
Write-Output "--------------------------------------"
Get-OrphanedProcesses
Write-Output "--------------------------------------"