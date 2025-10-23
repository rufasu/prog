# ===============================================
# install_bginfo.ps1
# �������������� ��������� BgInfo � ��������� �����
# ��������� ��������� � �������� ������
# ������� ����������� Windows
# ===============================================

# --- 1. �������� ���� �������������� ---
$IsAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
if (-not $IsAdmin) {
    Write-Host "��������� ����� ��������������. ����������..." -ForegroundColor Yellow
    Start-Process powershell -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
    exit
}

# --- 2. ��������� ��������� ---
$bginfoUrl      = "https://download.sysinternals.com/files/BGInfo.zip"
$bginfoPath     = "C:\programs\bginfo"
$bginfoExePath  = "$bginfoPath\bginfo.exe"
$configUrl      = "https://raw.githubusercontent.com/rufasu/prog/refs/heads/main/bgconfig.bgi"
$configPath     = "$bginfoPath\bgconfig.bgi"

# --- 3. ��������� ������������ ---
$SchedulerMode  = "AllUsers"   # ��������� ��������: SYSTEM, User, UserWithPass, AllUsers
$TaskUser       = ""           # ��� ������������ ��� User/UserWithPass
$TaskPassword   = ""           # ������ ��� UserWithPass (�������� ������ ��� User)

# --- 4. �������� ����� ��������� ---
if (-not (Test-Path $bginfoPath)) {
    New-Item -ItemType Directory -Path $bginfoPath -Force | Out-Null
    Write-Host "������� ����� $bginfoPath" -ForegroundColor Green
}

# --- 5. ���������� � ���������� BgInfo ---
$tempZip = "$env:TEMP\BgInfo.zip"
try {
    Write-Host "��������� BgInfo..." -ForegroundColor Cyan
    Invoke-WebRequest -Uri $bginfoUrl -OutFile $tempZip -ErrorAction Stop
    Write-Host "������������� BgInfo..." -ForegroundColor Cyan
    Expand-Archive -Path $tempZip -DestinationPath $bginfoPath -Force
    Remove-Item -Path $tempZip -Force
    Write-Host "BgInfo ������� ������ � ����������." -ForegroundColor Green
} catch {
    Write-Host "������ �������� BgInfo: $_" -ForegroundColor Red
    Pause
    exit 1
}

# --- 6. ���������� ����������������� ����� ---
try {
    Write-Host "��������� ���������������� ����..." -ForegroundColor Cyan
    Invoke-WebRequest -Uri $configUrl -OutFile $configPath -ErrorAction Stop
    Write-Host "������������ ���������: $configPath" -ForegroundColor Green
} catch {
    Write-Host "������ �������� �������: $_" -ForegroundColor Red
    Pause
    exit 1
}

# --- 7. �������� ������ � ������������ ---
try {
    $action   = New-ScheduledTaskAction -Execute $bginfoExePath -Argument "$configPath /timer:0 /NOLICPROMPT /silent"
    $trigger1 = New-ScheduledTaskTrigger -AtLogOn
    $trigger2 = New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes 1)
    $settings = New-ScheduledTaskSettingsSet -StartWhenAvailable `
                                             -DontStopOnIdleEnd `
                                             -AllowStartIfOnBatteries `
                                             -DontStopIfGoingOnBatteries

    switch ($SchedulerMode) {

        "SYSTEM" {
            Register-ScheduledTask -TaskName "BgInfo AutoRun" `
                                   -Action $action `
                                   -Trigger $trigger1, $trigger2 `
                                   -Settings $settings `
                                   -RunLevel Highest `
                                   -Force -ErrorAction Stop
            Write-Host "������ ������� �� SYSTEM." -ForegroundColor Green
        }

        "User" {
            if ([string]::IsNullOrWhiteSpace($TaskUser)) { throw "�� ������ ��� ������������ ��� ������ User." }
            Register-ScheduledTask -TaskName "BgInfo AutoRun" `
                                   -Action $action `
                                   -Trigger $trigger1, $trigger2 `
                                   -Settings $settings `
                                   -RunLevel Highest `
                                   -User $TaskUser `
                                   -Force -ErrorAction Stop
            Write-Host "������ ������� ��� ������������ $TaskUser (��� ������)." -ForegroundColor Green
        }

        "UserWithPass" {
            if ([string]::IsNullOrWhiteSpace($TaskUser) -or [string]::IsNullOrWhiteSpace($TaskPassword)) {
                throw "�� ������ ��� ������������ ��� ������ ��� ������ UserWithPass."
            }
            Register-ScheduledTask -TaskName "BgInfo AutoRun" `
                                   -Action $action `
                                   -Trigger $trigger1, $trigger2 `
                                   -Settings $settings `
                                   -RunLevel Highest `
                                   -User $TaskUser `
                                   -Password $TaskPassword `
                                   -Force -ErrorAction Stop
            Write-Host "������ ������� ��� ������������ $TaskUser � �������." -ForegroundColor Green
        }

        "AllUsers" {
            Write-Host "������ ������ ��� ���� ��������� ������������� (�������������� ��� ������������)..." -ForegroundColor Cyan

            $blockedUsers = @("�������","LOCAL SERVICE","NETWORK SERVICE","�����","Default","Public")
            $allowedGroups = @("��������������","������������")

            # �������� ���� ������������� �� ������� ��������
            $profileKeys = Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList"
            foreach ($key in $profileKeys) {
                try {
                    $sid = $key.PSChildName
                    $usernameFull = (New-Object System.Security.Principal.SecurityIdentifier($sid)).Translate([System.Security.Principal.NTAccount]).Value
                    $userOnly = $usernameFull.Split('\')[-1]

                    if ($blockedUsers -contains $userOnly) { continue }

                    # �������� �������� ������������ ����� ADSI
                    try {
                        $adsiUser = [ADSI]"WinNT://$env:COMPUTERNAME/$userOnly,user"
                        $userGroups = @($adsiUser.Groups() | ForEach-Object { $_.GetType().InvokeMember("Name",'GetProperty',$null,$_,$null) })
                        $isAllowed = ($userGroups -contains "��������������") -or ($userGroups -contains "������������")
                    } catch {
                        $isAllowed = $false
                    }

                    if ($isAllowed) {
                        $taskName = "BgInfo AutoRun_" + $userOnly
                        Write-Host ("������ ������ ��� ������������ " + $userOnly) -ForegroundColor Cyan
                        try {
                            Register-ScheduledTask -TaskName $taskName `
                                                   -Action $action `
                                                   -Trigger $trigger1, $trigger2 `
                                                   -Settings $settings `
                                                   -RunLevel Highest `
                                                   -User $usernameFull `
                                                   -Force -ErrorAction Stop
                        } catch {
                            Write-Host ("��������� ������ ��� " + $userOnly + ": " + $_) -ForegroundColor Yellow
                        }
                    } else {
                        Write-Host ("������������ " + $userOnly + " �������� (�� ������ � ����������� ������)") -ForegroundColor DarkYellow
                    }

                } catch {
                    Write-Host ("������ ��������� ������������ " + $userOnly + ": " + $_) -ForegroundColor Yellow
                }
            }
        }

        default { throw "�������� ����� SchedulerMode: $SchedulerMode" }
    }

    # --- 8. ����������� ������ BgInfo ---
    Start-Process -FilePath $bginfoExePath -ArgumentList "$configPath /timer:0 /NOLICPROMPT /silent"
    Write-Host "BgInfo ������� ����� ����� ���������." -ForegroundColor Green

} catch {
    Write-Host ("������ �������� ������ � ������������: " + $_) -ForegroundColor Red
}

# --- 9. ����� ��� ������������� �������� ---
Write-Host "`n������� ����� ������� ��� ������..." -ForegroundColor Yellow
$null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')
