$service_name = $args[0] #Valid Windows service name.
$service_state = $args[1] ##Running, Stopped
$handle_threshold = $args[2] #Integer
$pcpu_threshold = $args[3] #Integer
$pmem_threshold = $args[4] #Integer
$sysload_threshold = $args[5] #Integer
$dsthreshold = $args[6] #Percentage
$drive = $args[7] #Partition to Monitor
$url = $args[8] ## https://127.0.0.1:8447
$logpath = $args[9] ## C:\AppName\logs\monitor.log

#TODO:
# Add Webhook support for alert notification


#Variable declaration
$PERCENTAGE =
$Ipaddress =
$Port =
$handles =
$rescode =
$out_pid =
$pcpu =
$pmem =
$sys_load =

# function skipsslcheck() {
#     add-type @"
#     using System.Net;
#     using System.Security.Cryptography.X509Certificates;
#     public class TrustAllCertsPolicy : ICertificatePolicy {
#         public bool CheckValidationResult(
#             ServicePoint srvPoint, X509Certificate certificate,
#             WebRequest request, int certificateProblem) {
#             return true;
#         }
#     }
# "@
#     [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
# }

function checkdiskspace() {
    Get-Volume -DriveLetter $drive  2>&1 | out-null
    if ($?) {
        $FREE_SPACE = Get-Ciminstance Win32_LogicalDisk -Filter "DeviceID='${drive}:'" | ForEach-Object { [math]::truncate($_.freespace / 1GB) }
        $TOTAL_SPACE = Get-Ciminstance Win32_LogicalDisk -Filter "DeviceID='${drive}:'" | ForEach-Object { [math]::truncate($_.size / 1GB) }
        $script:PERCENTAGE = (($TOTAL_SPACE - $FREE_SPACE) * 100) / $TOTAL_SPACE
    
        if ($null -eq $PERCENTAGE) {
            return "ERR"
        }
        else {
            if ($PERCENTAGE -ge $dsthreshold) {
                # return "DSFAILED:($PERCENTAGE)"
                return "DSFAILED"
            }
            else {
                # return "DSSUCCESS:($PERCENTAGE)"
                return "DSSUCCESS"
            }
        }
    }
    else {
        return "ERR"
    }
}

function checkport() {
    ########PORT-CHECK###########
    $script:Ipaddress = $url -split "//" -split ":" | Select-Object -Last 2 | Select-Object -First 1
    $script:Port = $url -split "//" -split ":" | Select-Object -Last 2 | Select-Object -Last 1
    $ErrorActionPreference = 'silentlycontinue'
    $t = New-Object Net.Sockets.TcpClient -EA SilentlyContinue
    $t.Connect($Ipaddress, $Port)
    if ($t.Connected) {
        # return "PORTSUCCESS:($Port)"
        return "PORTSUCCESS"
    }
    else {
        # return "PORTFAILED:($Port)"
        return "PORTFAILED"
    }
}

function checkhandles() {
    $handles=(Get-Process | Where-Object 'Id' -eq "$out_pid").Handles
    Write-Output "File Handles:$handles || Handle Threshold:$handle_threshold"
    $script:handles = $handles
    if ($handles -gt "0") {
    if ($handles -gt $handle_threshold) {
        #return "HANDLESFAIL($handles)"
        return "HANDLESFAIL"
    } 
    else {
        #return "HANDLESSUCCESS($handles)"
        return "HANDLESSUCCESS"
	}
    }
    else {
        return "Handles:ERR"
    }

}

function checkcurl() {
    if ($url) {
        $script:rescode = curl --insecure -s -o /dev/null -w "%{http_code}" ${url}
        if (! $?) {
            if ($rescode -ne "200" -and $rescode -ne "302") {
                # return "CURLFAIL:($rescode)"
                return "CURLFAIL"
            }
            else {
                # return "CURLSUCCESS:($rescode)"
                return "CURLSUCCESS"
            }
        }
        else {
            return "CURLERR"
        }
    }
    else {
        return "SKIPURLCHECK"
    }
}
function checkpcpu() {
    ###Get CPU Load by Process
    $p = Tasklist /svc /fi "SERVICES eq $service_name" /fo csv | convertfrom-csv
    $script:out_pid = $p -split "=" -split ";" | Select-Object -Last 3 | Select-Object -First 1
    # $pcpu = Get-Process | Where-Object 'Id' -eq "$out_pid" | Select-Object 'CPU' | findstr /r "^[0-9]"
    $script:pcpu = (Get-Process -Id "$out_pid").CPU
    # $pcpu=[math]::Round($cpu,2)
    # Write-Output "$pcpu"
    if ($pcpu -ge 0) {
        if ($pcpu -gt $pcpu_threshold) {
            # return "PCPUFAILED:($pcpu)"
            return "PCPUFAILED"
        }
        else {
            # return "PCPUSUCCESS:($pcpu)"
            return "PCPUSUCCESS"
        }
    }
    else {
        return "PCPU:ERR"
    }
}

function checkpmem() {
    $p = Tasklist /svc /fi "SERVICES eq $service_name" /fo csv | convertfrom-csv
    $out_pid = $p -split "=" -split ";" | Select-Object -Last 3 | Select-Object -First 1
    # $pcpu = Get-Process | Where-Object 'Id' -eq "$out_pid" | Select-Object 'CPU' | findstr /r "^[0-9]"
    $script:pmem = ((Get-Process -Id "$out_pid").WS / 1024 / 1024)
    if ($pmem -gt $pmem_threshold) {
        # return "PMEMFAILED:($pmem)"
        return "PMEMFAILED"
    }
    else {
        # return "PMSUCCESS:($pmem)"
        return "PMEMSUCCESS"
    }
}

function checksysload() {
    $script:sys_load = (Get-CimInstance -Class Win32_Processor).LoadPercentage
    if ($sys_load -gt $sysload_threshold) {
        return "SYSLOADFAILED"
    }
    else {
        return "SYSLOADSUCCESS"
    }
}
#service name argument check
if ($service_name -and $handle_threshold -and $service_state -and $pcpu_threshold -and $sysload_threshold -and $drive -and $service_state -and $url -and $logpath) {
    #service name validation check.
    Get-Service -Name $service_name > $null
    if ($?) {
        # skipsslcheck 2>&1 | out-null
        $s_state = (Get-Service -Name $service_name).Status
        # Write-Output "Service State: $s_state"
        if ($s_state -eq $service_state) {
            #Write-Output "Service is in desire state($service_state)"
            #Get process ID
            $p = Tasklist /svc /fi "SERVICES eq $service_name" /fo csv | convertfrom-csv
            $out_pid = $p -split "=" -split ";" | Select-Object -Last 3 | Select-Object -First 1
            #Write-Output "PID: $out_pid"

            if ($out_pid) {
                # checkcurl
                # checkport
                # checkpcpu
                # checkhandles
                # checkdiskspace
                # curl and port checks
				##Get Uptime
				$puptime=(get-date).Subtract((Get-Process -Id $out_pid).starttime).Minutes
				##
                $chkurl = checkcurl
                if ($chkurl -ne "SKIPURLCHECK") {
                    if ($chkurl -ne "CURLERR") {
                        if ($chkurl -eq "CURLSUCCESS") {
                            # Write-Output "Curl Success."
                            $curlres = "SUCCESS"
                        }
                        else {
                            # Write-Output "Curl Failed with code."
                            $curlres = "FAILED"
                        }
                    } 
                    else {
                        # Write-Output "Curl Failed, Port closed."
                        $curlres = "FAILED"
                    }
                }
                else {
                    # Write-Output "Skipping URL check as URL wasn't given."
                    $curlres = "FAILED"
                }
                
                # Write-Output "Check port status:" 
                $cport = checkport
                
                if ($cport -eq "PORTSUCCESS") {
                    # Write-Output "Port is accessible."
                    $portres = "SUCCESS"
                }
                else {
                    # Write-Output "Port is not accessible."
                    $portres = "FAILED"
                }
                ######
                # $ds=checkdiskspace
                $chkdsp = checkdiskspace
                if ($chkdsp -ne "ERR") {
                    if ($chkdsp -eq "DSSUCCESS") {
                        # Write-Output "Disk space under control."
                        $dsres = "SUCCESS"
                    }
                    else {
                        # Write-Output "Disk space above threshold"
                        $dsres = "FAILED"
                    }
                }
                else {
                    # Write-Output "[!] No Drive found with associated letter"
                    Write-Output "Can't find the disk."
                }
                ###
                #checkhandles >> $logpath
                $chandles = checkhandles
                if ($chandles -eq "HANDLESSUCCESS") {
                    # Write-Output "File handles are below threshold."
                    $handleres = "SUCCESS"
                } 
                else {
                    #Write-Output "File handles($handles) are above threshold"
                    $handleres = "FAILED"
                }
                #####
                ## Check process CPU.
                $chkpcpu = checkpcpu
                if ($chkpcpu -ne "ERR") {
                    if ($chkpcpu -eq "PCPUSUCCESS") {
                        # Write-Output "Process CPU usage is below threshold."
                        $pcpures = "SUCCESS"
                    }
                    else {
                        # Write-Output "Process CPU usage is above threshold"
                        $pcpures = "FAILED"
                    }
                }
                else {
                    # Write-Output "[!] Process CPU Usage not found."
                    $pcpures = "FAILED"
                }
            }
            else {
                # Write-Output "[!] PID not found restarting the service."
                Write-Output "FAIL:PID not found for $service_name"
            }
            ####
            ## Check System load.
            $chksysload = checksysload
            if ($chksysload -eq "SYSLOADSUCCESS") {
                # Write-Output "Sysload is below given threshold."
                $loadres = "SUCCESS"
            }
            else {
                # Write-Output "Sysload is above threshold."
                $loadres = "FAILED"
            }
            ####
            ## Check Process memory.
            $chkpmem = checkpmem
            if ($chkpmem -eq "PMEMSUCCESS") {
                # Write-Output "Sysload is below given threshold."
                $pmemres = "SUCCESS"
            }
            else {
                # Write-Output "Sysload is above threshold."
                $pmemres = "FAILED"
            }

            #--------Action Block---------#
            if (($loadres -eq "FAILED" ) -and ($pcpures -eq "FAILED" ) -and ($pmemres -eq "FAILED" )) { 
                # Write-Output "Load, CPU and Memory usage are above threshold."
                Write-Output "$(Get-Date)|| Uptime[m]($puptime) || LoadAVG($sys_load) & CPU Usage($pcpu) and Memory($pmem) Usage is above threshold, Restarting the service($service_name)." >> $logpath
                Restart-Service -Name $service_name
                Write-Output "FAIL:loadavg-$loadavg,processcpu-$pcpu,processme-$pmem are above given threshold ,Restarting the service($service_name)."
            }
            elseif (($loadres -eq "FAILED" ) -and ($pcpures -eq "FAILED" )) {
                # Write-Output "LoadAVG & CPU Avg are high."
                Write-Output "$(Get-Date)|| Uptime[m]($puptime) || LoadAVG($sys_load) & CPU Usage($pcpu) is above threshold($sysload_threshold ,$pcpu_threshold), Restarting the service($service_name)." >> $logpath
                Restart-Service -Name $service_name
                Write-Output "FAIL:load avg-$loadavg,process cpu-$pcpu are above given threshold, Restarting the service($service_name)."
            }
            elseif (($portres -eq "FAILED") -and ($curlres -eq "FAILED")) {
                # Write-Output "Port($Port) isn't accessible OR Curl($url) request is failing, Restarting the service"
                Write-Output "$(Get-Date)|| Uptime[m]($puptime) || Port($Port) isn't accessible OR Curl($url) request is failing, Restarting the service($service_name)." >> $logpath
                Restart-Service -Name $service_name
                Write-Output "FAIL:Port-$Port isn't accessible and Curl($Ipaddress $Port) request is failing, Restarting the service($service_name)."
            }
            elseif ($portres -eq "FAILED") {
                # Write-Output "Port($Port) isn't accessible, Restarting the service"
                Write-Output "$(Get-Date)|| Uptime[m]($puptime) || Port($Port) isn't accessible, Restarting the service($service_name)." >> $logpath
                Restart-Service -Name $service_name
                Write-Output "FAIL:Port-$Port isn't accessible, Restarting the service($service_name)."
            }
            elseif ($handleres -eq "FAILED") {
                #checkhandles >> $logpath
                Write-Output "$(Get-Date) || Uptime[m]($puptime) || [!] Restarting service($service_name) as filehandles($handles) is above given threshold($handle_threshold)." >> $logpath
                Restart-Service -Name $service_name
                Write-Output "FAIL:filehandles-$filehandles are above threshold, Restarting the service($service_name)."
            }
			elseif ($dsres -eq "FAILED") {
                # Write-Output "Running out of diskspace($PERCENTAGE), please check."
                Write-Output "$(Get-Date) || [!] Diskspace($PERCENTAGE) is above threshold($dsthreshold)" >> $logpath
                Write-Output "List of files above 500MB in $drive drive." >> $logpath
                Get-ChildItem "${drive}:\" -recurse -ErrorAction SilentlyContinue | where-object {$_.Length -gt 500*1024*1024} | Sort-Object length | ft length,fullname >> $logpath
                Write-Output "FAIL:$PERCENTAGE Diskspace is above threshold"
            }
            else {
                # Write-Output "Good for now."
                Write-Output "SUCCESS:Good for now."
            }
            
        }
        else {
            Write-Output "[#] Service is not in desire state, getting it in desire state."
            if ($service_state -eq "Running") {
                Write-Output "$(Get-Date) || [!] Starting service($service_name) as requested in desire state" >> $logpath
                Start-Service -Name $service_name
                Write-Output "FAIL:Starting $service_name to get it into desire state."
            }
            else {
                Write-Output "$(Get-Date) || [!] Stopping service($service_name) as requested in desire state" >> $logpath
                Stop-Service -Name $service_name
                Write-Output "FAIL:Stopping $service_name to get it into desire state."
            }
        }
    }
    else {
        # Write-Host "[!] Invalid service name service($service_name) not found!"
        Write-Output "FAIL:service($service_name) name is invalid."
    }
}
else {
    Write-Output "FAIL:Missing one or many arguments."
    Write-Host "[!] One or many arguments are missing!
    Given Inputs:
    ServiceName:[Valid Windows service name]= $service_name	
    ServiceState:[Running, Stopped]= $service_state 	
    FileHandle_Threshold= $handle_threshold
    ProcessCPU_Threshold= $pcpu_threshold	
    ProcessMem_Threshold= $pmem_threshold	
    SysLoad_Threshold= $sysload_threshold
    DiskSpace_Thresholds= $dsthreshold	
    Drive-[Partition to Monitor]= $drive 			
    URL:[https://127.0.0.1:8447]= $url			
    OutputLog:[C:\APPName\logs\monitor.log]= $logpath"
}
