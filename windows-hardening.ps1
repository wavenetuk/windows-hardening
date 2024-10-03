<#
    .DESCRIPTION
    Windows Hardening Script
#>

Param (
    [Parameter(Mandatory = $true)]
    [ValidateNotNullorEmpty()]
    [string] $adminUsername,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullorEmpty()]
    [string] $pw
)

begin {
    function Write-Log {
        [CmdletBinding()]
        <#
            .SYNOPSIS
            Create log function
        #>
        param (
            [Parameter(Mandatory = $True)]
            [ValidateNotNullOrEmpty()]
            [System.String] $logPath,

            [Parameter(Mandatory = $True)]
            [ValidateNotNullOrEmpty()]
            [System.String] $object,

            [Parameter(Mandatory = $True)]
            [ValidateNotNullOrEmpty()]
            [System.String] $message,

            [Parameter(Mandatory = $True)]
            [ValidateNotNullOrEmpty()]
            [ValidateSet('Information', 'Warning', 'Error', 'Verbose', 'Debug')]
            [System.String] $severity,

            [Parameter(Mandatory = $False)]
            [Switch] $toHost
        )

        begin {
            $date = (Get-Date).ToLongTimeString()
        }
        process {
            if (($severity -eq "Information") -or ($severity -eq "Warning") -or ($severity -eq "Error") -or ($severity -eq "Verbose" -and $VerbosePreference -ne "SilentlyContinue") -or ($severity -eq "Debug" -and $DebugPreference -ne "SilentlyContinue")) {
                if ($True -eq $toHost) {
                    Write-Host $date -ForegroundColor Cyan -NoNewline
                    Write-Host " - [" -ForegroundColor White -NoNewline
                    Write-Host "$object" -ForegroundColor Yellow -NoNewline
                    Write-Host "] " -ForegroundColor White -NoNewline
                    Write-Host ":: " -ForegroundColor White -NoNewline

                    Switch ($severity) {
                        'Information' {
                            Write-Host "$message" -ForegroundColor White
                        }
                        'Warning' {
                            Write-Warning "$message"
                        }
                        'Error' {
                            Write-Host "ERROR: $message" -ForegroundColor Red
                        }
                        'Verbose' {
                            Write-Verbose "$message"
                        }
                        'Debug' {
                            Write-Debug "$message"
                        }
                    }
                }
            }

            switch ($severity) {
                "Information" { [int]$type = 1 }
                "Warning" { [int]$type = 2 }
                "Error" { [int]$type = 3 }
                'Verbose' { [int]$type = 2 }
                'Debug' { [int]$type = 2 }
            }

            if (!(Test-Path (Split-Path $logPath -Parent))) { New-Item -Path (Split-Path $logPath -Parent) -ItemType Directory -Force | Out-Null }

            $content = "<![LOG[$message]LOG]!>" + `
                "<time=`"$(Get-Date -Format "HH:mm:ss.ffffff")`" " + `
                "date=`"$(Get-Date -Format "M-d-yyyy")`" " + `
                "component=`"$object`" " + `
                "context=`"$([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)`" " + `
                "type=`"$type`" " + `
                "thread=`"$([Threading.Thread]::CurrentThread.ManagedThreadId)`" " + `
                "file=`"`">"
            if (($severity -eq "Information") -or ($severity -eq "Warning") -or ($severity -eq "Error") -or ($severity -eq "Verbose" -and $VerbosePreference -ne "SilentlyContinue") -or ($severity -eq "Debug" -and $DebugPreference -ne "SilentlyContinue")) {
                Add-Content -Path $($logPath + ".log") -Value $content
            }
        }
        end {}
    }

    $LogPath = "$env:SYSTEMROOT\TEMP\Deployment_" + (Get-Date -Format 'yyyy-MM-dd')
}

process {
    # Get Operating System Product Name
    $OS = (Get-CimInstance -ClassName 'Win32_OperatingSystem').Name.Split('|')[0]

    # Rename Built-in Administrator Account
    Rename-LocalUser -SID (Get-LocalUser | Where-Object { $_.SID -like 'S-1-5-*-500' }).Sid.Value -NewName "_Administrator"
    Write-Log -Object "Hardening" -Message "Renamed Administrator account" -Severity Information -LogPath $LogPath

    # Disable Built-in Administrator Account
    Disable-LocalUser -SID (Get-LocalUser | Where-Object { $_.SID -like 'S-1-5-*-500' }).Sid.Value
    Write-Log -Object "Hardening" -Message "Disabled SID500 Administator account" -Severity Information -LogPath $LogPath

    # Remove Built-in Admin Profile
    Get-CimInstance -Class Win32_UserProfile | Where-Object { $_.SID -like 'S-1-5-*-500' } | Remove-CimInstance
    Write-Log -Object "Hardening" -Message "Removed SID500 Administator account profile" -Severity Information -LogPath $LogPath

    # Create New Admin
    New-LocalUser $adminUsername -Password (ConvertTo-SecureString $pw -AsPlainText -Force) -Description "Local Administrator" -PasswordNeverExpires | Out-Null
    Add-LocalGroupMember -Group 'Administrators' -Member $adminUsername | Out-Null
    Remove-LocalGroupMember -Group 'Users' -Member $adminUsername -ErrorAction SilentlyContinue | Out-Null
    Write-Log -Object "Hardening" -Message "Created new local Administrator account" -Severity Information -LogPath $LogPath

    # Rename Guest Account
    Rename-LocalUser -Name "Guest" -NewName "_Guest"
    Write-Log -Object "Hardening" -Message "Renamed Guest account" -Severity Information -LogPath $LogPath

    # Disable Guest Account
    Disable-LocalUser -Name "_Guest"
    Write-Log -Object "Hardening" -Message "Disabled Guest account" -Severity Information -LogPath $LogPath

    # Set time source
    $Computer = Get-WmiObject -Namespace root\cimv2 -Class Win32_ComputerSystem
    if ($Computer.Domain -ne "WORKGROUP") {
        Set-ItemProperty -LiteralPath 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\W32Time\Parameters\' -Name "Type" -Value 'NT5DS' -ErrorAction SilentlyContinue
        Set-ItemProperty -LiteralPath 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders\VMICTimeProvider\' -Name "Enabled" -Value 0 -ErrorAction SilentlyContinue
        Get-Service -Name "W32Time" | Restart-Service
        Write-Log -Object "Hardening" -Message "Set Time Source to NT5DS" -Severity Information -LogPath $LogPath
    }

    # Expand OS Partition to Max
    $Disk = Get-Disk | Where-Object IsSystem -eq $True
    $Partition = $Disk | Get-Partition | Where-Object IsBoot -eq $True
    $MaxSize = (Get-PartitionSupportedSize -DiskNumber $Disk.Number -PartitionNumber $Partition.PartitionNumber).SizeMax
    Resize-Partition -DiskNumber $Disk.Number -PartitionNumber $Partition.PartitionNumber -Size $MaxSize -ErrorAction SilentlyContinue
    Write-Log -Object "Hardening" -Message "Expanded System Partition to $MaxSize" -Severity Information -LogPath $LogPath

    # Change Optical Drive to Z:
    $Optical = Get-CimInstance -Class Win32_CDROMDrive | Select-Object -ExpandProperty Drive
    if (!($null -eq $Optical) -and !($Optical -eq 'Z:')) {
        Set-CimInstance -InputObject ( Get-CimInstance -Class Win32_volume -Filter "DriveLetter = '$Optical'" ) -Arguments @{DriveLetter = 'Z:' } | Out-Null
        Write-Log -Object "Hardening" -Message "Set Optical Drive to Z:" -Severity Information -LogPath $LogPath
    }

    # Enable Crash Dumps
    Set-ItemProperty -LiteralPath 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\CrashControl\' -Name 'CrashDumpEnabled' -Value 3 -ErrorAction SilentlyContinue
    Write-Log -Object "Hardening" -Message "Enabled Crash Dumps" -Severity Information -LogPath $LogPath

    # Set Advanced Audit Policy
    $auditPolList = @(
        "System"
        "Logon/Logoff"
        "Object Access"
        "Privilege Use"
        "Detailed Tracking"
        "Account Management"
        "DS Access"
        "Account Logon"
    )
    foreach ($policy in $auditPolList) {
        auditpol /set /category:$policy /failure:enable /success:enable
        Write-Log -Object "Hardening" -Message "Configured Advanced Audit Policy: $policy" -Severity Information -LogPath $LogPath
    }

    # Reregister performance counters
    Start-Process C:\Windows\System32\lodctr.exe -ArgumentList '/q' -NoNewWindow -Wait
    Write-Log -Object "Hardening" -Message "Reregistered performance counters" -Severity Information -LogPath $LogPath

    # Set Eventlog Sizes
    Limit-EventLog -LogName Application -MaximumSize 81920KB -OverflowAction OverwriteAsNeeded
    Limit-EventLog -LogName Security -MaximumSize 81920KB -OverflowAction OverwriteAsNeeded
    Limit-EventLog -LogName System -MaximumSize 81920KB -OverflowAction OverwriteAsNeeded
    Write-Log -Object "Hardening" -Message "Set EventLog Size" -Severity Information -LogPath $LogPath

    # Allow ping through windows firewall
    New-NetFirewallRule -DisplayName 'Allow ICMPv4-In' -Direction Inbound -Action Allow -Protocol ICMPv4 -ErrorAction SilentlyContinue | Out-Null
    New-NetFirewallRule -DisplayName 'Allow ICMPv6-In' -Direction Inbound -Action Allow -Protocol ICMPv6 -ErrorAction SilentlyContinue | Out-Null
    Write-Log -Object "Hardening" -Message "Confgiured Windows Firewall to allow Ping" -Severity Information -LogPath $LogPath

    # Disable Windows Powershell V2
    if ($OS -like "*Server*") {
        Remove-WindowsFeature -Name PowerShell-V2 -ErrorAction SilentlyContinue | Out-Null
    }
    else {
        Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root -ErrorAction SilentlyContinue | Out-Null
    }
    Write-Log -Object "Hardening" -Message "Uninstalled PowerShell V2" -Severity Information -LogPath $LogPath

    # Enable Telnet Client
    if ($OS -like "*Server*") {
        Install-WindowsFeature -Name Telnet-Client -ErrorAction SilentlyContinue | Out-Null
    }
    else {
        Enable-WindowsOptionalFeature -Online -FeatureName TelnetClient -ErrorAction SilentlyContinue | Out-Null
    }
    Write-Log -Object "Hardening" -Message "Installed Telnet Client" -Severity Information -LogPath $LogPath

    # Enable Remote Powershell
    Enable-PSRemoting -SkipNetworkProfileCheck -Confirm:$false -ErrorAction SilentlyContinue | Out-Null
    Write-Log -Object "Hardening" -Message "Enabled PowerShell remoting" -Severity Information -LogPath $LogPath

    # Stop and Disable Print Spooler
    if ($OS -like "*Server*") {
        Set-Service -Name Spooler -StartupType Disabled | Out-Null
        Stop-Service -Name Spooler -Force  | Out-Null
        Write-Log -Object "Hardening" -Message "Disabled Print Spooler Service" -Severity Information -LogPath $LogPath
    }

    # Disable ieESC
    Set-ItemProperty -LiteralPath 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}' -Name 'IsInstalled' -Value 0 -ErrorAction SilentlyContinue
    Set-ItemProperty -LiteralPath 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A8-37EF-4b3f-8CFC-4F3A74704073}' -Name 'IsInstalled' -Value 0 -ErrorAction SilentlyContinue
    Write-Log -Object "Hardening" -Message "Disabled ieESC" -Severity Information -LogPath $LogPath

    # Configure TLS/SSL
    # TLS 1.0
    New-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\' -Name 'TLS 1.0' -ErrorAction SilentlyContinue | Out-Null
    New-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0' -Name 'Client' -ErrorAction SilentlyContinue | Out-Null
    New-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0' -Name 'Server' -ErrorAction SilentlyContinue | Out-Null
    New-ItemProperty -LiteralPath 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client' -Name 'Enabled' -PropertyType DWord -Value '0' -ErrorAction SilentlyContinue | Out-Null
    New-ItemProperty -LiteralPath 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client' -Name 'DisabledByDefault' -PropertyType DWord -Value '1' -ErrorAction SilentlyContinue | Out-Null
    New-ItemProperty -LiteralPath 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server' -Name 'Enabled' -PropertyType DWord -Value '0' -ErrorAction SilentlyContinue | Out-Null
    New-ItemProperty -LiteralPath 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server' -Name 'DisabledByDefault' -PropertyType DWord -Value '1' -ErrorAction SilentlyContinue | Out-Null

    # TLS 1.1
    New-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\' -Name 'TLS 1.1' -ErrorAction SilentlyContinue | Out-Null
    New-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1' -Name 'Client' -ErrorAction SilentlyContinue | Out-Null
    New-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1' -Name 'Server' -ErrorAction SilentlyContinue | Out-Null
    New-ItemProperty -LiteralPath 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client' -Name 'Enabled' -PropertyType DWord -Value '0' -ErrorAction SilentlyContinue | Out-Null
    New-ItemProperty -LiteralPath 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client' -Name 'DisabledByDefault' -PropertyType DWord -Value '1' -ErrorAction SilentlyContinue | Out-Null
    New-ItemProperty -LiteralPath 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server' -Name 'Enabled' -PropertyType DWord -Value '0' -ErrorAction SilentlyContinue | Out-Null
    New-ItemProperty -LiteralPath 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server' -Name 'DisabledByDefault' -PropertyType DWord -Value '1' -ErrorAction SilentlyContinue | Out-Null

    # TLS 1.2
    New-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\' -Name 'TLS 1.2' -ErrorAction SilentlyContinue | Out-Null
    New-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2' -Name 'Client' -ErrorAction SilentlyContinue | Out-Null
    New-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2' -Name 'Server' -ErrorAction SilentlyContinue | Out-Null
    New-ItemProperty -LiteralPath 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client' -Name 'Enabled' -PropertyType DWord -Value '1' -ErrorAction SilentlyContinue | Out-Null
    New-ItemProperty -LiteralPath 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client' -Name 'DisabledByDefault' -PropertyType DWord -Value '0' -ErrorAction SilentlyContinue | Out-Null
    New-ItemProperty -LiteralPath 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server' -Name 'Enabled' -PropertyType DWord -Value '1' -ErrorAction SilentlyContinue | Out-Null
    New-ItemProperty -LiteralPath 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server' -Name 'DisabledByDefault' -PropertyType DWord -Value '0' -ErrorAction SilentlyContinue | Out-Null

    # SSL 2.0
    New-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\' -Name 'SSL 2.0' -ErrorAction SilentlyContinue | Out-Null
    New-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0' -Name 'Client' -ErrorAction SilentlyContinue | Out-Null
    New-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0' -Name 'Server' -ErrorAction SilentlyContinue | Out-Null
    New-ItemProperty -LiteralPath 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client' -Name 'Enabled' -PropertyType DWord -Value '0' -ErrorAction SilentlyContinue | Out-Null
    New-ItemProperty -LiteralPath 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client' -Name 'DisabledByDefault' -PropertyType DWord -Value '1' -ErrorAction SilentlyContinue | Out-Null
    New-ItemProperty -LiteralPath 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server' -Name 'Enabled' -PropertyType DWord -Value '0' -ErrorAction SilentlyContinue | Out-Null
    New-ItemProperty -LiteralPath 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server' -Name 'DisabledByDefault' -PropertyType DWord -Value '1' -ErrorAction SilentlyContinue | Out-Null

    #SSL 3.0
    New-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\' -Name 'SSL 3.0' -ErrorAction SilentlyContinue | Out-Null
    New-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0' -Name 'Client' -ErrorAction SilentlyContinue | Out-Null
    New-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0' -Name 'Server' -ErrorAction SilentlyContinue | Out-Null
    New-ItemProperty -LiteralPath 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client' -Name 'Enabled' -PropertyType DWord -Value '0' -ErrorAction SilentlyContinue | Out-Null
    New-ItemProperty -LiteralPath 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client' -Name 'DisabledByDefault' -PropertyType DWord -Value '1' -ErrorAction SilentlyContinue | Out-Null
    New-ItemProperty -LiteralPath 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server' -Name 'Enabled' -PropertyType DWord -Value '0' -ErrorAction SilentlyContinue | Out-Null
    New-ItemProperty -LiteralPath 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server' -Name 'DisabledByDefault' -PropertyType DWord -Value '1' -ErrorAction SilentlyContinue | Out-Null

    # dotnet 2 SSL
    New-Item -Path 'HKLM:\SOFTWARE\Microsoft\.NETFramework\' -Name 'v2.0.50727' -ErrorAction SilentlyContinue | Out-Null
    New-Item -Path 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\' -Name 'v2.0.50727' -ErrorAction SilentlyContinue | Out-Null
    New-ItemProperty -LiteralPath 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\.NETFramework\v2.0.50727' -Name 'SystemDefaultTlsVersions' -PropertyType DWord -Value '1' -ErrorAction SilentlyContinue | Out-Null
    New-ItemProperty -LiteralPath 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\.NETFramework\v2.0.50727' -Name 'SchUseStrongCrypto' -PropertyType DWord -Value '1' -ErrorAction SilentlyContinue | Out-Null
    New-ItemProperty -LiteralPath 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v2.0.50727' -Name 'SystemDefaultTlsVersions' -PropertyType DWord -Value '1' -ErrorAction SilentlyContinue | Out-Null
    New-ItemProperty -LiteralPath 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v2.0.50727' -Name 'SchUseStrongCrypto' -PropertyType DWord -Value '1' -ErrorAction SilentlyContinue | Out-Null

    # dotnet 4 SSL
    New-Item -Path 'HKLM:\SOFTWARE\Microsoft\.NETFramework\' -Name 'v4.0.30319' -ErrorAction SilentlyContinue | Out-Null
    New-Item -Path 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\' -Name 'v4.0.30319' -ErrorAction SilentlyContinue | Out-Null
    New-ItemProperty -LiteralPath 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\.NETFramework\v4.0.30319' -Name 'SystemDefaultTlsVersions' -PropertyType DWord -Value '1' -ErrorAction SilentlyContinue | Out-Null
    New-ItemProperty -LiteralPath 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\.NETFramework\v4.0.30319' -Name 'SchUseStrongCrypto' -PropertyType DWord -Value '1' -ErrorAction SilentlyContinue | Out-Null
    New-ItemProperty -LiteralPath 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v4.0.30319' -Name 'SystemDefaultTlsVersions' -PropertyType DWord -Value '1' -ErrorAction SilentlyContinue | Out-Null
    New-ItemProperty -LiteralPath 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v4.0.30319' -Name 'SchUseStrongCrypto' -PropertyType DWord -Value '1' -ErrorAction SilentlyContinue | Out-Null

    Write-Log -Object "Hardening" -Message "Configured TLS/SSL" -Severity Information -LogPath $LogPath

    # Allow IE file downloads
    Set-ItemProperty -LiteralPath 'Registry::HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3\' -Name '1803' -Value 0 -ErrorAction SilentlyContinue
    Write-Log -Object "Hardening" -Message "Allow IE File Downloads" -Severity Information -LogPath $LogPath

    # Disable Protected Mode Banner in IE
    Set-ItemProperty -LiteralPath 'Registry::HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Internet Explorer\Main' -Name 'NoProtectedModeBanner' -Value 1 -ErrorAction SilentlyContinue
    Write-Log -Object "Hardening" -Message "Disabled IE Protected Mode Banner" -Severity Information -LogPath $LogPath

    # Disable IE First Run Wizard:
    New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\' -Name 'Internet Explorer' -ErrorAction SilentlyContinue | Out-Null
    New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer' -Name 'Main' -ErrorAction SilentlyContinue | Out-Null
    New-ItemProperty -LiteralPath 'Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Internet Explorer\Main' -Name 'DisableFirstRunCustomize' -Value 1  -ErrorAction SilentlyContinue | Out-Null
    Write-Log -Object "Hardening" -Message "Disable IE First Run Wizard" -Severity Information -LogPath $LogPath

    # Disable WAC Prompt
    if ($OS -like "*Server*") {
        Set-ItemProperty -LiteralPath 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\ServerManager' -Name 'DoNotPopWACConsoleAtSMLaunch' -Value 1 -ErrorAction SilentlyContinue
        Write-Log -Object "Hardening" -Message "Disabled WAC Prompt" -Severity Information -LogPath $LogPath
    }

    # Set VM to High Perf scheme
    POWERCFG -SetActive '8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c'
    Write-Log -Object "Hardening" -Message "Set VM to High Performance" -Severity Information -LogPath $LogPath

    # Disable Hard Disk Timeouts
    POWERCFG /SETACVALUEINDEX 381b4222-f694-41f0-9685-ff5bb260df2e 0012ee47-9041-4b5d-9b77-535fba8b1442 6738e2c4-e8a5-4a42-b16a-e040e769756e 0
    POWERCFG /SETDCVALUEINDEX 381b4222-f694-41f0-9685-ff5bb260df2e 0012ee47-9041-4b5d-9b77-535fba8b1442 6738e2c4-e8a5-4a42-b16a-e040e769756e 0
    Write-Log -Object "Hardening" -Message "Disable Hard Disk Timeouts" -Severity Information -LogPath $LogPath

    # Disable Hibernate
    POWERCFG -h off
    Write-Log -Object "Hardening" -Message "Disable Hibernate" -Severity Information -LogPath $LogPath

    # Disable New Network Dialog
    New-Item -Path 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Network' -Name 'NewNetworkWindowOff' -ErrorAction SilentlyContinue | Out-Null
    Write-Log -Object "Hardening" -Message "Disable New Network Dialog" -Severity Information -LogPath $LogPath

    # Disable LLMNR
    New-Item -Path 'HKLM:\SOFTWARE\policies\Microsoft\Windows NT\' -Name 'DNSClient' -ErrorAction SilentlyContinue | Out-Null
    New-ItemProperty -LiteralPath 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\policies\Microsoft\Windows NT\DNSClient' -Name 'EnableMulticast' -PropertyType DWord -Value 0 -ErrorAction SilentlyContinue | Out-Null
    Write-Log -Object "Hardening" -Message "Disable LLMNR" -Severity Information -LogPath $LogPath

    # Disable NetBIOS
    $key = "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces"
    Get-ChildItem $key | ForEach-Object { Set-ItemProperty -Path "$key\$($_.pschildname)" -Name NetbiosOptions -Value 2 | Out-Null }
    Write-Log -Object "Hardening" -Message "Disable NetBIOS" -Severity Information -LogPath $LogPath

    # Enable Task Manager Disk Performance Counters
    diskperf -Y | Out-Null
    Write-Log -Object "Hardening" -Message "Enable Task Manager Disk Performance Counters" -Severity Information -LogPath $LogPath

    # Modify SMB defaults
    Disable-WindowsOptionalFeature -Online -FeatureName 'SMB1Protocol' -NoRestart | Out-Null
    Write-Log -Object "Hardening" -Message "Disable SMB1" -Severity Information -LogPath $LogPath

    # SMB Modifications for performance:
    New-ItemProperty -LiteralPath 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' -Name 'DisableBandwidthThrottling' -PropertyType DWord -Value '1' -ErrorAction SilentlyContinue | Out-Null
    New-ItemProperty -LiteralPath 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' -Name 'DisableLargeMtu' -PropertyType DWord -Value '0' -ErrorAction SilentlyContinue | Out-Null
    New-ItemProperty -LiteralPath 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' -Name 'FileInfoCacheEntriesMax' -PropertyType DWord -Value '8000' -ErrorAction SilentlyContinue | Out-Null
    New-ItemProperty -LiteralPath 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' -Name 'DirectoryCacheEntriesMax' -PropertyType DWord -Value '1000' -ErrorAction SilentlyContinue | Out-Null
    New-ItemProperty -LiteralPath 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' -Name 'FileNotFoundcacheEntriesMax' -PropertyType DWord -Value '1' -ErrorAction SilentlyContinue | Out-Null
    New-ItemProperty -LiteralPath 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' -Name 'MaxCmds' -PropertyType DWord -Value '8000' -ErrorAction SilentlyContinue | Out-Null
    New-ItemProperty -LiteralPath 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' -Name 'EnableWsd' -PropertyType DWord -Value '0' -ErrorAction SilentlyContinue | Out-Null

    # Enable SMB signing
    Set-ItemProperty -LiteralPath 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanWorkStation\Parameters' -Name "RequireSecuritySignature" -Value 1 -ErrorAction SilentlyContinue
    Set-ItemProperty -LiteralPath 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -Name "RequireSecuritySignature" -Value 1 -ErrorAction SilentlyContinue
    Set-ItemProperty -LiteralPath 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanWorkStation\Parameters' -Name "EnableSecuritySignature" -Value 1 -ErrorAction SilentlyContinue
    Set-ItemProperty -LiteralPath 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -Name "EnableSecuritySignature" -Value 1 -ErrorAction SilentlyContinue

    # Disable Autoplay
    Set-ItemProperty -LiteralPath 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name "NoDriveTypeAutoRun" -Value 255 -ErrorAction SilentlyContinue
    Write-Log -Object "Hardening" -Message "Disable Autoplay" -Severity Information -LogPath $LogPath

    # Disable Null Session Access
    Set-ItemProperty -LiteralPath 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -Name "RestrictNullSessAccess" -Value 1 -ErrorAction SilentlyContinue
    Set-ItemProperty -LiteralPath 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa' -Name "RestrictAnonymous" -Value 1 -ErrorAction SilentlyContinue
    Set-ItemProperty -LiteralPath 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa' -Name "RestrictAnonymousSAM" -Value 1 -ErrorAction SilentlyContinue
    Set-ItemProperty -LiteralPath 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa' -Name "EveryoneIncludesAnonymous" -Value 0 -ErrorAction SilentlyContinue
    Write-Log -Object "Hardening" -Message "Disable Null Sessions" -Severity Information -LogPath $LogPath

    # Remove (Almost All) Inbox UWP Apps:
    if ($OS -notlike "*Server*") {
        # Get list of Provisioned Start Screen Apps
        $Apps = Get-ProvisionedAppxPackage -Online

        # Disable "Consumer Features" (aka downloading apps from the internet automatically)
        New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\' -Name 'CloudContent' -ErrorAction SilentlyContinue | Out-Null
        New-ItemProperty -LiteralPath 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\CloudContent' -Name 'DisableWindowsConsumerFeatures' -PropertyType DWord -Value '1' -ErrorAction SilentlyContinue | Out-Null
        # Disable the "how to use Windows" contextual popups
        New-ItemProperty -LiteralPath 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\CloudContent' -Name 'DisableSoftLanding' -PropertyType DWord -Value '1' -ErrorAction SilentlyContinue | Out-Null

        $appsToRemove = @('Clipchamp.Clipcham',
            'Microsoft.3DBuilder',
            'Microsoft.549981C3F5F10',
            'Microsoft.BingFinance',
            'Microsoft.BingNews',
            'Microsoft.BingSports',
            'Microsoft.BingWeather',
            'Microsoft.CommsPhone',
            'Microsoft.ConnectivityStore',
            'Microsoft.GamingApp',
            'Microsoft.GetHelp',
            'Microsoft.Getstarted',
            'Microsoft.Messaging',
            'Microsoft.Microsoft.XboxIdentityProvider',
            'Microsoft.Microsoft3DViewer',
            'Microsoft.MicrosoftOfficeHub',
            'Microsoft.MicrosoftSolitaireCollection',
            'Microsoft.MixedReality.Portal',
            'Microsoft.Office.OneNote',
            'Microsoft.Office.Sway',
            'Microsoft.OneConnect',
            'Microsoft.People',
            'Microsoft.PowerAutomateDesktop',
            'Microsoft.SkypeApp',
            'Microsoft.Todos',
            'Microsoft.Wallet',
            'Microsoft.Windows.Photos',
            'Microsoft.WindowsAlarms',
            'Microsoft.WindowsCamera',
            'Microsoft.WindowsCommunicationsApps',
            'Microsoft.WindowsFeedbackHub',
            'Microsoft.WindowsMaps',
            'Microsoft.WindowsPhone',
            'Microsoft.WindowsSoundRecorder',
            'Microsoft.Xbox.TCUI',
            'Microsoft.XboxApp',
            'Microsoft.XboxGameOverlay',
            'Microsoft.XboxGamingOverlay',
            'Microsoft.XboxIdentityProvider',
            'Microsoft.XboxSpeechToTextOverlay',
            'Microsoft.YourPhone',
            'Microsoft.ZuneMusic',
            'Microsoft.ZuneVideo'
        )

        # Remove Windows Store Apps
        ForEach ($App in $Apps) {
            If ($App.DisplayName -in $appsToRemove) {
                Remove-AppxProvisionedPackage -Online -PackageName $App.PackageName | Out-Null
                Remove-AppxPackage -Package $App.PackageName | Out-Null
                Write-Log -Object "Hardening" -Message "Removed $($App.DisplayName)" -Severity Information -LogPath $LogPath
            }
        }

        # Update Windows Store Apps
        $namespaceName = "root\cimv2\mdm\dmmap"
        $className = "MDM_EnterpriseModernAppManagement_AppManagement01"
        $result = Get-CimInstance -Namespace $namespaceName -Class $className | Invoke-CimMethod -MethodName UpdateScanMethod
    }

    # Install NuGet
    try {
        $Provider = 'NuGet'
        Write-Log -Object "Hardening" -Message "PowerShell Provider $Provider installing" -Severity Information -LogPath $LogPath
        Install-PackageProvider -Name $Provider -Confirm:$False -Force | Out-Null
        Write-Log -Object "Hardening" -Message "PowerShell Provider $Provider installed" -Severity Information -LogPath $LogPath
    }
    catch {
        $ErrorMessage = $_.Exception.Message
        if ($Null -eq $ErrorMessage) {
            Write-Log -Object "Hardening" -Message "PowerShell Provider $Provider failed to install" -Severity Error -LogPath $LogPath
        }
        else {
            Write-Log -Object "Hardening" -Message "$ErrorMessage" -Severity Error -LogPath $LogPath
        }
    }
    # Install PSWindowsUpdate
    try {
        $Module = 'PSWindowsUpdate'
        Write-Log -Object "Hardening" -Message "PowerShell Module $Module installing" -Severity Information -LogPath $LogPath
        Install-Module -Name $Module -Confirm:$false -Force | Out-Null
        Write-Log -Object "Hardening" -Message "PowerShell Module $Module installed" -Severity Information -LogPath $LogPath
    }
    catch {
        $ErrorMessage = $_.Exception.Message
        if ($Null -eq $ErrorMessage) {
            Write-Log -Object "Hardening" -Message "PowerShell Module $Module failed to install" -Severity Error -LogPath $LogPath
        }
        else {
            Write-Log -Object "Hardening" -Message "$ErrorMessage" -Severity Error -LogPath $LogPath
        }
    }

    <# Install Windows Updates
    $updates = Get-WindowsUpdate -MicrosoftUpdate -Category 'Critical Updates', 'Definition Updates', 'Security Updates'
    while (![string]::IsNullOrEmpty($updates)) {
        try {
            Write-Log -Object "Hardening" -Message "Installing Windows Updates" -Severity Information -LogPath $LogPath
            Install-WindowsUpdate -MicrosoftUpdate -Category 'Critical Updates', 'Definition Updates', 'Security Updates' -AcceptAll
        }
        catch {
            $ErrorMessage = $_.Exception.Message
            if ($Null -eq $ErrorMessage) {
                Write-Log -Object "Hardening" -Message "Failed to install Windows Updates" -Severity Error -LogPath $LogPath
            }
            else {
                Write-Log -Object "Hardening" -Message "$ErrorMessage" -Severity Error -LogPath $LogPath
            }
        }
        $updates = Get-WindowsUpdate -MicrosoftUpdate -Category 'Critical Updates', 'Definition Updates', 'Security Updates'
    }
    Write-Log -Object "Hardening" -Message "Installed Windows Updates" -Severity Information -LogPath $LogPath -ToHost
#>
}

end {
    # Restart Computer
    Restart-Computer -Force
}
