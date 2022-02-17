Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/skalingclouds/inception/master/bootstrap11dev.ps1' -OutFile .\bootstrap11dev.ps1; .\bootstrap11dev.ps1
Write-Host "Starting Post Deploy..."
$Logfile = $MyInvocation.MyCommand.Path -replace '\.ps1$', '.log'
 
Start-Transcript -Path $Logfile
 
#Doing some stuff with the Verbose parameter
 
Get-ChildItem -Verbose
 
Get-Service -Verbose
 
Get-Process -Verbose
 
Write-Output 'Writing some text to the log file'
 
Stop-Transcript
#########fc