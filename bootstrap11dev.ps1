
## Download latest Release From Github
$ErrorActionPreference = "Continue"
$ModulesToBeInstalled = (
    'Az',
    'Configuration',
    'posh-git',
    'Terminal-Icons',
    'posh-git',
    'PSreadline',
    'PowerLine'
)

##Install Winget Packages##
$WingetInstalls = (
    "microsoft.powershell",
    "Microsoft.Powershell.Preview",
    "Git.Git",
    "Microsoft.WindowsTerminal.Preview",
    "7zip.7zip",
    "gpu-z",
    "cpu-z",
    "hwinfo",
    'AMD.RyzenMaster',
    "vscode",
    "PrimateLabs.Geekbench.5",
    "Unigine.HeavenBenchmark",
    "Unigine.superpositionBenchmark",
    "Microsoft.dotnetRuntime.5-x64",
    "Microsoft.dotnetRuntime.6-x64",
    "BleachBit.BleachBit",
    "M2Team.NanaZip",
    "Microsoft.VC++2015-2019Redist-x86",
    "JanDeDobbeleer.OhMyPosh",
    "Voidtools.Everything",
    "Discord.Discord",
    'Microsoft.dotnetRuntime.5-x64',
    'Microsoft.dotnetRuntime.6-x64',
    'BleachBit.BleachBit',
    'Microsoft.VC++2015-2019Redist-x86',
    'Geeks3D.MSIKombustor',
    'Flow-Launcher.Flow-Launcher'
)

$ChocoPackages = (
    "amd-ryzen-chipset"
)


#InstallWinGet
function InstallWinGet() {
    #$hasPackageManager = Get-AppPackage -name "Microsoft.DesktopAppInstaller"

    #if (!$hasPackageManager) {
    $releases_url = "https://api.github.com/repos/microsoft/winget-cli/releases/latest"

    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $releases = Invoke-RestMethod -Uri "$($releases_url)"
    $latestRelease = $releases.assets | Where-Object { $_.browser_download_url.EndsWith("msixbundle") } | Select-Object -First 1
	
    Add-AppxPackage -Path $latestRelease.browser_download_url
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; Install-Module -Name PackageManagement -Force -MinimumVersion 1.4.7 -Scope CurrentUser -AllowClobber -Repository PSGallery
    #}
}

function InstallPackageManagers {
    #Install Choco
    Write-Host "Installing Choco..."
    Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
    #Install Scoop
    #Write-Host "Installing Scoop"
    #Invoke-Expression (New-Object System.Net.WebClient).DownloadString('https://get.scoop.sh')
}
function InstallWinGetPackages {
    foreach ($WingetInstall in $WingetInstalls) {
        powershell.exe winget install $WingetInstall --accept-package-agreements --accept-source-agreements -h -e 
        Write-Host "$WingetInstall has been installed"
    }
}
Function InstallPowerShellModules() {
    # Install/Update PowershellGet and PackageManager if needed
    try {
        Import-Module PowerShellGet
    }
    catch {
        throw 'Unable to load PowerShellGet!'
    }

    $packages = Get-Package
    if (@($packages | Where-Object { $_.Name -eq 'PackageManagement' }).Count -eq 0) {
        Write-Host -ForegroundColor cyan "PackageManager is installed but not being maintained via the PowerShell gallery (so it will never get updated). Forcing the install of this module through the gallery to rectify this now."
        Install-Module PackageManagement -Force
        Install-Module PowerShellGet -Force
        Write-Host -ForegroundColor:Red "PowerShellGet and PackageManagement have been installed from the gallery. You need to close and rerun this script for them to work properly!"
    }
    else {
        $InstalledModules = (Get-InstalledModule).name
        $ModulesToBeInstalled = $ModulesToBeInstalled | Where-Object { $InstalledModules -notcontains $_ }

    }
}
function GetGithubReleases() {
    If (-not (Test-Path $UtilDownloadPath)) {
        mkdir $UtilDownloadPath -Force
    }
    If (-not (Test-Path $UtilBinPath)) {
        mkdir $UtilBinPath -Force
    }
    $FilesDownloaded = @()

    Foreach ($software in $GithubReleasesPackages.keys) {
        $releases = "https://api.github.com/repos/$software/releases"
        Write-Output "Determining latest release for repo $Software"
        $tag = (Invoke-WebRequest $releases -UseBasicParsing | ConvertFrom-Json)[0]
        $tag.assets | ForEach-Object {
            $DownloadPath = (Join-Path $UtilDownloadPath $_.Name)
            if ($_.name -like $GithubReleasesPackages[$software]) {
                if ( -not (Test-Path $_.Name)) {
                    try {
                        Write-Output "Downloading $($_.Name)..."
                        Invoke-WebRequest -ContentType "application/octet-stream" $_.'browser_download_url' -OutFile $DownloadPath
                        $FilesDownloaded += $_.Name
                    }
                    catch {}
                }
                else {
                    Write-Warning "File is already downloaded, skipping: $($_.Name)"
                }
            }
        }
    }
}
#Manual Downloads    
Function ManualDownload() {
    Foreach ($software in $ManualDownloadInstall.keys) {
        Write-Output "Downloading $software"
        $DownloadPath = (Join-Path $UtilDownloadPath $software)
        if ( -not (Test-Path $DownloadPath) ) {
            try {
                Invoke-WebRequest -ContentType "application/octet-stream" $ManualDownloadInstall[$software] -OutFile $DownloadPath -UseBasicParsing
                $FilesDownloaded += $software
            }
            catch {}
        }
        else {
            Write-Warning "File is already downloaded, skipping: $software"
        }
    }

    # Extracting self-contained binaries (zip files) to our bin folder
    Write-Output 'Extracting self-contained binaries (zip files) to our bin folder'
    Get-ChildItem -Path $UtilDownloadPath -File -Filter '*.zip' | Where-Object { $FilesDownloaded -contains $_.Name } | ForEach-Object {
        Expand-Archive -Path $_.FullName -DestinationPath (Join-Path $UtilBinPath ($_.name).split('.')[0]) -Force }

    #Kick off exe installs
    #Get-ChildItem -Path $UtilDownloadPath -File -Filter '*.exe' | Where-Object { $FilesDownloaded -contains $_.Name -and $_.Name -notcontains "*[Guru3D.com]*" } | foreach {
    #    Start-Proc -Exe $_.FullName $Arguments  -waitforexit
    #}
    # Kick off msi installs
    ##Get-ChildItem -Path $UtilDownloadPath -File -Filter '*.msi' | Where {$FilesDownloaded -contains $_.Name} | Foreach {
    #    Start-Proc -Exe $_.FullName -waitforexit
    #}
}

#Teaks
#Function InstallTweaks {
#DisableMemoryCompression
#Disable-MMAgent -mc
#bcdedit /set useplatformclock true
#bcdedit /set tscsyncpolicy Enhanced
#bcdedit /set disabledynamictick yes
#Utlimate Power Plan"
#"Write-Output Disabling DMA memory protection and cores isolation..."
#$ErrorActionPreference = "silentlycontinue"
#bcdedit /set vsmlaunchtype Off | Out-Null
#bcdedit /set vm No | Out-Null
# New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" | Out-Null -ErrorAction SilentlyContinue
#Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "DisableExternalDMAUnderLock" -Type DWord -Value 0
#New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" | Out-Null -ErrorAction SilentlyContinue
#Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" -Name "EnableVirtualizationBasedSecurity" -Type DWord -Value 0
#Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" -Name "HVCIMATRequired" -Type DWord -Value 0
#Disable Process and Kernel Mitigations
#Write-Output "Disabling Process and Kernel Mitigations..."
#$errpref = $ErrorActionPreference #save actual preference
#$ErrorActionPreference = "silentlycontinue"
#ForEach ($v in (Get-Command -Name "Set-ProcessMitigation").Parameters["Disable"].Attributes.ValidValues) { Set-ProcessMitigation -System -Disable $v.ToString() -ErrorAction SilentlyContinue }
#Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" -Name "DisableExceptionChainValidation" -Type DWord -Value 1
#Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" -Name "KernelSEHOPEnabled" -Type DWord -Value 0
#Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "EnableCfg" -Type DWord -Value 0
#}

#Install Drivers
function Install-LatestNvidiaDriver() {
    Param (
        [switch]$clean = $false, # Will delete old drivers and install the new ones
        [string]$folder = "$env:temp"   # Downloads and extracts the driver here
    )

    # Checking currently installed driver version
    Write-Host "Attempting to detect currently installed driver version..."

    $VideoController = Get-WmiObject -ClassName Win32_VideoController | Where-Object { $_.Name -match "NVIDIA" }
    $ins_version = ($VideoController.DriverVersion.Replace('.', '')[-5..-1] -join '').insert(3, '.')
    Write-Host "Installed version `t$ins_version"
    if ($version -eq $ins_version) {
        Write-Host "The installed version is the same as the latest version."
    }
    else {

        $scheduleTask = $false  # Creates a Scheduled Task to run to check for driver updates
        $scheduleDay = "Sunday" # When should the scheduled task run (Default = Sunday)
        $scheduleTime = "12pm"  # The time the scheduled task should run (Default = 12pm)

        # Checking if 7zip or WinRAR are installed
        # Check 7zip install path on registry
        $7zipinstalled = $false
        if ((Test-Path HKLM:\SOFTWARE\7-Zip\) -eq $true) {
            $7zpath = Get-ItemProperty -Path HKLM:\SOFTWARE\7-Zip\ -Name Path
            $7zpath = $7zpath.Path
            $7zpathexe = $7zpath + "7z.exe"
            if ((Test-Path $7zpathexe) -eq $true) {
                $archiverProgram = $7zpathexe
                $7zipinstalled = $true
            }
        }
        else {
            Write-Host "it looks like you don't have a supported archiver."
            Write-Host "Downloading 7zip Now"
            # Download and silently install 7-zip if the user presses y
            $7zip = "https://www.7-zip.org/a/7z1900-x64.exe"
            $output = "$PSScriptRoot\7Zip.exe"
            (New-Object System.Net.WebClient).DownloadFile($7zip, $output)
            Start-Process "7Zip.exe" -Wait -ArgumentList "/S"
            # Delete the installer once it completes
            Remove-Item "$PSScriptRoot\7Zip.exe"
        }
        # Checking latest driver version from Nvidia website
        $link = Invoke-WebRequest -Uri 'https://www.nvidia.com/Download/processFind.aspx?psid=101&pfid=816&osid=57&lid=1&whql=1&lang=en-us&ctk=0&dtcid=0' -Method GET -UseBasicParsing
        $link -match '<td class="gridItem">([^<]+?)</td>' | Out-Null
        $version = $matches[1]
        Write-Host "Latest version `t`t$version"
        # Comparing installed driver version to latest driver version from Nvidia
        # Checking Windows version
        if ([Environment]::OSVersion.Version -ge (New-Object 'Version' 9, 1)) {
            $windowsVersion = "win10"
        }
        else {
            $windowsVersion = "win8-win7"
        }
        # Checking Windows bitness
        if ([Environment]::Is64BitOperatingSystem) {
            $windowsArchitecture = "64bit"
        }
        else {
            $windowsArchitecture = "32bit"
        }
        # Create a new temp folder NVIDIA
        $nvidiaTempFolder = "$folder\NVIDIA"
        New-Item -Path $nvidiaTempFolder -ItemType Directory 2>&1 | Out-Null
        # Generating the download link
        $url = "https://international.download.nvidia.com/Windows/$version/$version-desktop-$windowsVersion-$windowsArchitecture-international-whql.exe"
        $rp_url = "https://international.download.nvidia.com/Windows/$version/$version-desktop-$windowsVersion-$windowsArchitecture-international-whql-rp.exe"
        # Downloading the installer
        $dlFile = "$nvidiaTempFolder\$version.exe"
        Write-Host "Downloading the latest version to $dlFile"
        Start-BitsTransfer -Source $url -Destination $dlFile
        if ($?) {
            Write-Host "Proceed..."
        }
        else {
            Write-Host "Download failed, trying alternative RP package now..."
            Start-BitsTransfer -Source $rp_url -Destination $dlFile
        }
        # Extracting setup files
        $extractFolder = "$nvidiaTempFolder\$version"
        $filesToExtract = "Display.Driver HDAudio NVI2 PhysX EULA.txt ListDevices.txt setup.cfg setup.exe"
        Write-Host "Download finished, extracting the files now..."
        if ($7zipinstalled) {
            Start-Process -FilePath $archiverProgram -NoNewWindow -ArgumentList "x -bso0 -bsp1 -bse1 -aoa $dlFile $filesToExtract -o""$extractFolder""" -Wait
        }
        elseif ($archiverProgram -eq $winrarpath) {
            Start-Process -FilePath $archiverProgram -NoNewWindow -ArgumentList 'x $dlFile $extractFolder -IBCK $filesToExtract' -Wait
        }
        else {
            Write-Host "Something went wrong. No archive program detected. This should not happen."
            Write-Output "Something went wrong. No archive program detected. This should not happen." | Out-File "C:\NvidiaErrorLog.Log" -Append
        }
        # Remove unneeded dependencies from setup.cfg
        (Get-Content "$extractFolder\setup.cfg") | Where-Object { $_ -notmatch 'name="\${{(EulaHtmlFile|FunctionalConsentFile|PrivacyPolicyFile)}}' } | Set-Content "$extractFolder\setup.cfg" -Encoding UTF8 -Force
        # Installing drivers
        Write-Host "Installing Nvidia drivers now..."
        $install_args = "-passive -noreboot -noeula -nofinish -s"
        if ($clean) {
            $install_args = $install_args + " -clean"
        }
        Start-Process -FilePath "$extractFolder\setup.exe" -ArgumentList $install_args -Wait
        # Creating a scheduled task if the $scheduleTask varible is set to TRUE
        if ($scheduleTask) {
            Write-Host "Creating A Scheduled Task..."
            New-Item C:\Task\ -type directory 2>&1 | Out-Null
            Copy-Item .\Nvidia.ps1 -Destination C:\Task\ 2>&1 | Out-Null
            $taskname = "Nvidia-Updater"
            $description = "Update Your Driver!"
            $action = New-ScheduledTaskAction -Execute "C:\Task\Nvidia.ps1"
            $trigger = New-ScheduledTaskTrigger -Weekly -WeeksInterval $scheduleTask -DaysOfWeek $scheduleDay -At $scheduleTime
            Register-ScheduledTask -TaskName $taskname -Action $action -Trigger $trigger -Description $description 2>&1 | Out-Null
        }
        # Cleaning up downloaded files
        Write-Host "Deleting downloaded files"
        Remove-Item $nvidiaTempFolder -Recurse -Force
    }
}
#Kick off Windows Cleanup
function Start-WindowsCleanup() {
    If (!(Test-Path -Path "C:\WinCleanupComplete.txt")) {
        Set-StrictMode -Version Latest
        $ProgressPreference = 'SilentlyContinue'
        $ErrorActionPreference = 'SilentlyContinue'
        trap {
            Write-Host
            Write-Host "ERROR: $_"
            Write-Host (($_.ScriptStackTrace -split '\r?\n') -replace '^(.*)$', 'ERROR: $1')
            Write-Host (($_.Exception.ToString() -split '\r?\n') -replace '^(.*)$', 'ERROR EXCEPTION: $1')

        }
        #
        # enable TLS 1.1 and 1.2.
        [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol 
            -bor [Net.SecurityProtocolType]::Tls11 
            -bor [Net.SecurityProtocolType]::Tls12
        #
        # run automatic maintenance.

        Add-Type @'
using System;
using System.Runtime.InteropServices;
public static class Windows
{
    [DllImport("kernel32", SetLastError=true)]
    public static extern UInt64 GetTickCount64();
    public static TimeSpan GetUptime()
    {
        return TimeSpan.FromMilliseconds(GetTickCount64());
    }
}
'@

        function Wait-Condition {
            param(
                [scriptblock]$Condition,
                [int]$DebounceSeconds = 15
            )
            process {
                $begin = [Windows]::GetUptime()
                do {
                    Start-Sleep -Seconds 3
                    try {
                        $result = &$Condition
                    }
                    catch {
                        $result = $false
                    }
                    if (-not $result) {
                        $begin = [Windows]::GetUptime()
                        continue
                    }
                } while ((([Windows]::GetUptime()) - $begin).TotalSeconds -lt $DebounceSeconds)
            }
        }

        function Get-ScheduledTasks() {
            $s = New-Object -ComObject 'Schedule.Service'
            try {
                $s.Connect()
                Get-ScheduledTasksInternal $s.GetFolder('\')
            }
            finally {
                [System.Runtime.Interopservices.Marshal]::ReleaseComObject($s) | Out-Null
            }
        }
        function Get-ScheduledTasksInternal($Folder) {
            $Folder.GetTasks(0)
            $Folder.GetFolders(0) | ForEach-Object {
                Get-ScheduledTasksInternal $_
            }
        }
        function Test-IsMaintenanceTask([xml]$definition) {
            # see MaintenanceSettings (maintenanceSettingsType) Element at https://msdn.microsoft.com/en-us/library/windows/desktop/hh832151(v=vs.85).aspx
            $ns = New-Object System.Xml.XmlNamespaceManager($definition.NameTable)
            $ns.AddNamespace('t', $definition.DocumentElement.NamespaceURI)
            $null -ne $definition.SelectSingleNode("/t:Task/t:Settings/t:MaintenanceSettings", $ns)
        }

        Write-Host 'Running Automatic Maintenance...'
        MSchedExe.exe Start
        Wait-Condition { @(Get-ScheduledTasks | Where-Object { ($_.State -ge 4) -and (Test-IsMaintenanceTask $_.XML) }).Count -eq 0 } -DebounceSeconds 60
        #
        # generate the .net frameworks native images.
        # NB this is normally done in the Automatic Maintenance step, but for
        #    some reason, sometimes its not.update
        # see https://docs.microsoft.com/en-us/dotnet/framework/tools/ngen-exe-native-image-generator

        Get-ChildItem "$env:windir\Microsoft.NET\*\*\ngen.exe" | ForEach-Object {
            Write-Host "Generating the .NET Framework native images with $_..."
            &$_ executeQueuedItems /nologo /silent | Out-File "$UtilDownloadPath\WindowsCleanup.log" -Append
        }
        #
        # remove temporary files.
        # NB we ignore the packer generated files so it won't complain in the output.

        Write-Host 'Stopping services that might interfere with temporary file removal...'
        function Stop-ServiceForReal($name) {
            while ($true) {
                Stop-Service -ErrorAction SilentlyContinue $name
                if ((Get-Service $name).Status -eq 'Stopped') {
                    break
                }
            }
        }
        Stop-ServiceForReal TrustedInstaller   # Windows Modules Installer
        Stop-ServiceForReal wuauserv           # Windows Update
        Stop-ServiceForReal BITS               # Background Intelligent Transfer Service
        @(
            "$env:LOCALAPPDATA\Temp\*"
            "$env:windir\Temp\*"
            "$env:windir\Logs\*"
            "$env:windir\Panther\*"
            "$env:windir\WinSxS\ManifestCache\*"
            "$env:windir\SoftwareDistribution\Download"
        ) | Where-Object { Test-Path $_ } | ForEach-Object {
            Write-Host "Removing temporary files $_..."
            takeown.exe /D Y /R /F $_ | Out-Null
            icacls.exe $_ /grant:r Administrators:F /T /C /Q 2>&1  | Out-File "$UtilDownloadPath\WindowsCleanup.log" -Append
        }

        # cleanup the WinSxS folder.

        # NB even thou the automatic maintenance includes a component cleanup task,
        #    it will not clean everything, as such, dism will clean the rest.
        # NB to analyse the used space use: dism.exe /Online /Cleanup-Image /AnalyzeComponentStore
        # see https://docs.microsoft.com/en-us/windows-hardware/manufacture/desktop/clean-up-the-winsxs-folder
        Write-Host 'Cleaning up the WinSxS folder...'
        dism.exe /Online /Quiet /Cleanup-Image /StartComponentCleanup /ResetBase | Out-File "$UtilDownloadPath\WindowsCleanup.log" -Append
        if ($LASTEXITCODE) {
            throw "Failed with Exit Code $LASTEXITCODE"
        }

        #even after cleaning up the WinSxS folder the "Backups and Disabled Features"
        #    field of the analysis report will display a non-zero number because the
        #    disabled features packages are still on disk. you can remove them with:
        #Get-WindowsOptionalFeature -Online "
        # | Where-Object { $_.State -eq 'Disabled' } "
        # | ForEach-Object {
        #    Write-Host "Removing feature $($_.FeatureName)..."
        #    dism.exe /Online /Quiet /Disable-Feature "/FeatureName:$($_.FeatureName)" /Remove | Out-File "$UtilDownloadPath\WindowsCleanup.log" -Append
        #}
        #    NB a removed feature can still be installed from other sources (e.g. windows update).
        Write-Host 'Analyzing the WinSxS folder...'
        dism.exe /Online /Cleanup-Image /AnalyzeComponentStore | Out-File "$UtilDownloadPath\WindowsCleanup.log" -Append
        DISM.EXE /Online /Cleanup-Image /ScanHealth | Out-File "$UtilDownloadPath\WindowsCleanup.log"
        DISM.EXE /online /Cleanup-Image /StartComponentCleanup /ResetBase | Out-File "$UtilDownloadPath\WindowsCleanup.log" -Append
        Dism.exe /online /Cleanup-Image /SPSuperseded | Out-File "$UtilDownloadPath\WindowsCleanup.log" -Append
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Active Setup Temp Folders" -Name -type "StateFlags0001"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\BranchCache" -Name "StateFlags0001" -Type DWord -Value 2
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\D3D Shader Cache" -Name "StateFlags0001" -Type DWord -Value 2
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Delivery Optimization Files" -Name "StateFlags0001" -Type DWord -Value 2
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Diagnostic Data Viewer database files" -Name "StateFlags0001" -Type DWord -Value 2
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Downloaded Program Files" -Name "StateFlags0001" -Type DWord -Value 2
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Internet Cache Files" -Name "StateFlags0001" -Type DWord -Value 2
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Language Pack" -Name "StateFlags0001" -Type DWord -Value 2
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Old ChkDsk Files" -Name "StateFlags0001" -Type DWord -Value 2
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Recycle Bin" -Name "StateFlags0001" -Type DWord -Value 2
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\RetailDemo Offline Content" -Name "StateFlags0001" -Type DWord -Value 2
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Setup Log Files" -Name "StateFlags0001" -Type DWord -Value 2
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\System error memory dump files" -Name "StateFlags0001" -Type DWord -Value 2
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\System error minidump files" -Name "StateFlags0001" -Type DWord -Value 2
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Temporary Files" -Name "StateFlags0001" -Type DWord -Value 2
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Thumbnail Cache" -Name "StateFlags0001" -Type DWord -Value 2
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Update Cleanup" -Name "StateFlags0001" -Type DWord -Value 2
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\User file versions" -Name "StateFlags0001" -Type DWord -Value 2
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Windows Defender" -Name "StateFlags0001" -Type DWord -Value 2
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Windows Error Reporting Files" -Name "StateFlags0001" -Type DWord -Value 2
        cleanmgr.exe /SAGERUN:1
        #
        # reclaim the free disk space.

        Write-Host 'Reclaiming the free disk space...'
        $results = defrag.exe C: /H /L /B /O "$UtilDownloadPath\WindowsCleanup.log"
        if ($results -eq 'The operation completed successfully.') {
            $results
        }
        else {
            Write-Host 'Zero filling the free disk space...'
            (New-Object System.Net.WebClient).DownloadFile('https://download.sysinternals.com/files/SDelete.zip', "$env:TEMP\SDelete.zip")
            Expand-Archive "$env:TEMP\SDelete.zip" $env:TEMP
            Remove-Item "$env:TEMP\SDelete.zip"
            &"$env:TEMP\sdelete64.exe" -accepteula -z C:
        }
        Start-Service TrustedInstaller   # Windows Modules Installer
        Start-Service wuauserv           # Windows Update
        Start-Service BITS
        #sfc.exe /scannow
        Write-Output "Finished Windows Cleanup, Creating text file as flag to not run again" | Out-File "C:\WinCleanupComplete.txt"
    }
    else {
        Write-Output "Windows Cleanup Already Ran"
    }
}

function CopyLicenses {
    Copy-Item - 
}

function TinyNvidiaUpdateChecker {

    Start-Process "C:\Users\ZenMini\OneDrive\Tools\Essential Tool Set\13 - Core System\ZenBoxSetup\Windows11AutoConfigure\TinyNvidiaUpdateChecker.exe --quiet --confirm-dl"  

}
InstallWinGet
mkdir "C:\ZenBoxSetup\UtilBin"
$UtilBinPath = "C:\ZenBoxSetup\UtilBin"
mkdir "C:\ZenboxSetup\Downloads"
$UtilDownloadPath = "C:\ZenboxSetup\Downloads"
[Net.ServicePointManager]::SecurityProtocol = [System.Security.Authentication.SslProtocols] "tls, tls11, tls12"
Set-ExecutionPolicy -ExecutionPolicy Bypass -Force
Write-Host -ForegroundColor 'Yellow' 'Setting PSGallery as a trusted installation source...'
Set-PSRepository -Name PSGallery -InstallationPolicy Trusted

InstallWinGet
InstallPackageManagers
InstallWinGetPackages
InstallPowerShellModules
cinst amd-ryzen-chipset -y
Start-WindowsCleanup
Reboot-Computer
