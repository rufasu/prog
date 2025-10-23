# ===============================================
# install_bginfo.ps1
# Автоматическая установка BgInfo с созданием задач
# Поддержка локальной и удалённой сессии
# Русская локализация Windows
# ===============================================

# Глобальная настройка TLS для всех запросов (fallback, если Schannel ок)
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# Helper-функция: Скачивание с retry (IWR -> WebClient)
function Download-FileWithRetry {
    param(
        [string]$Uri,
        [string]$OutFile,
        [switch]$UseBasicParsing = $true
    )
    try {
        # Попытка 1: Invoke-WebRequest (с TLS и BasicParsing)
        Write-Host "Попытка скачивания через Invoke-WebRequest..." -ForegroundColor Gray
        Invoke-WebRequest -Uri $Uri -OutFile $OutFile -UseBasicParsing:$UseBasicParsing -ErrorAction Stop
        Write-Host "Скачано через IWR." -ForegroundColor Gray
    } catch {
        Write-Host "IWR провал: $($_.Exception.Message). Переход на WebClient..." -ForegroundColor Yellow
        try {
            # Попытка 2: WebClient (fallback, с User-Agent)
            $wc = New-Object System.Net.WebClient
            $wc.Headers.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36")
            if ($Uri -match '\.zip|\.bgi$') {
                # Бинарный файл (ZIP/.bgi)
                $wc.DownloadFile($Uri, $OutFile)
            } else {
                # Текст (если нужно, но здесь не используется)
                $wc.DownloadString($Uri) | Out-File -FilePath $OutFile -Encoding UTF8
            }
            Write-Host "Скачано через WebClient." -ForegroundColor Green
        } catch {
            Write-Host "WebClient провал: $($_.Exception.Message)" -ForegroundColor Red
            throw $_
        }
    }
}

# --- 1. Проверка прав администратора ---
$IsAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
if (-not $IsAdmin) {
    Write-Host "Требуются права администратора. Перезапуск..." -ForegroundColor Yellow
    Start-Process powershell -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
    exit
}

# --- 2. Настройки установки ---
$bginfoUrl      = "https://download.sysinternals.com/files/BGInfo.zip"
$bginfoPath     = "C:\programs\bginfo"
$bginfoExePath  = "$bginfoPath\bginfo.exe"
$configUrl      = "https://raw.githubusercontent.com/rufasu/prog/main/bgconfig.bgi"
$configPath     = "$bginfoPath\bgconfig.bgi"

# --- 3. Настройки планировщика ---
$SchedulerMode  = "AllUsers"   # Возможные значения: SYSTEM, User, UserWithPass, AllUsers
$TaskUser       = ""           # Имя пользователя для User/UserWithPass
$TaskPassword   = ""           # Пароль для UserWithPass (оставить пустым для User)

# --- 4. Создание папки установки ---
if (-not (Test-Path $bginfoPath)) {
    New-Item -ItemType Directory -Path $bginfoPath -Force | Out-Null
    Write-Host "Создана папка $bginfoPath" -ForegroundColor Green
}

# --- 5. Скачивание и распаковка BgInfo ---
$tempZip = "$env:TEMP\BgInfo.zip"
try {
    Write-Host "Скачиваем BgInfo..." -ForegroundColor Cyan
    Download-FileWithRetry -Uri $bginfoUrl -OutFile $tempZip
    Write-Host "Распаковываем BgInfo..." -ForegroundColor Cyan
    Expand-Archive -Path $tempZip -DestinationPath $bginfoPath -Force
    Remove-Item -Path $tempZip -Force
    Write-Host "BgInfo успешно скачан и распакован." -ForegroundColor Green
} catch {
    Write-Host "Ошибка загрузки BgInfo: $_" -ForegroundColor Red
    Pause
    exit 1
}

# --- 6. Скачивание конфигурационного файла ---
try {
    Write-Host "Скачиваем конфигурационный файл..." -ForegroundColor Cyan
    Download-FileWithRetry -Uri $configUrl -OutFile $configPath
    Write-Host "Конфигурация загружена: $configPath" -ForegroundColor Green
} catch {
    Write-Host "Ошибка загрузки конфига: $_" -ForegroundColor Red
    Pause
    exit 1
}

# --- 7. Создание задачи в планировщике ---
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
            Write-Host "Задача создана от SYSTEM." -ForegroundColor Green
        }

        "User" {
            if ([string]::IsNullOrWhiteSpace($TaskUser)) { throw "Не задано имя пользователя для режима User." }
            Register-ScheduledTask -TaskName "BgInfo AutoRun" `
                                   -Action $action `
                                   -Trigger $trigger1, $trigger2 `
                                   -Settings $settings `
                                   -RunLevel Highest `
                                   -User $TaskUser `
                                   -Force -ErrorAction Stop
            Write-Host "Задача создана для пользователя $TaskUser (без пароля)." -ForegroundColor Green
        }

        "UserWithPass" {
            if ([string]::IsNullOrWhiteSpace($TaskUser) -or [string]::IsNullOrWhiteSpace($TaskPassword)) {
                throw "Не задано имя пользователя или пароль для режима UserWithPass."
            }
            Register-ScheduledTask -TaskName "BgInfo AutoRun" `
                                   -Action $action `
                                   -Trigger $trigger1, $trigger2 `
                                   -Settings $settings `
                                   -RunLevel Highest `
                                   -User $TaskUser `
                                   -Password $TaskPassword `
                                   -Force -ErrorAction Stop
            Write-Host "Задача создана для пользователя $TaskUser с паролем." -ForegroundColor Green
        }

        "AllUsers" {
            Write-Host "Создаём задачи для всех локальных пользователей (Администраторы или Пользователи)..." -ForegroundColor Cyan

            $blockedUsers = @("СИСТЕМА","LOCAL SERVICE","NETWORK SERVICE","Гость","Default","Public")
            $allowedGroups = @("Администраторы","Пользователи")

            # Получаем всех пользователей из реестра профилей
            $profileKeys = Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList"
            foreach ($key in $profileKeys) {
                try {
                    $sid = $key.PSChildName
                    $usernameFull = (New-Object System.Security.Principal.SecurityIdentifier($sid)).Translate([System.Security.Principal.NTAccount]).Value
                    $userOnly = $usernameFull.Split('\')[-1]

                    if ($blockedUsers -contains $userOnly) { continue }

                    # Проверка членства пользователя через ADSI
                    try {
                        $adsiUser = [ADSI]"WinNT://$env:COMPUTERNAME/$userOnly,user"
                        $userGroups = @($adsiUser.Groups() | ForEach-Object { $_.GetType().InvokeMember("Name",'GetProperty',$null,$_,$null) })
                        $isAllowed = ($userGroups -contains "Администраторы") -or ($userGroups -contains "Пользователи")
                    } catch {
                        $isAllowed = $false
                    }

                    if ($isAllowed) {
                        $taskName = "BgInfo AutoRun_" + $userOnly
                        Write-Host ("Создаём задачу для пользователя " + $userOnly) -ForegroundColor Cyan
                        try {
                            Register-ScheduledTask -TaskName $taskName `
                                                   -Action $action `
                                                   -Trigger $trigger1, $trigger2 `
                                                   -Settings $settings `
                                                   -RunLevel Highest `
                                                   -User $usernameFull `
                                                   -Force -ErrorAction Stop
                        } catch {
                            Write-Host ("Пропущена задача для " + $userOnly + ": " + $_) -ForegroundColor Yellow
                        }
                    } else {
                        Write-Host ("Пользователь " + $userOnly + " пропущен (не входит в разрешённые группы)") -ForegroundColor DarkYellow
                    }

                } catch {
                    Write-Host ("Ошибка обработки пользователя " + $userOnly + ": " + $_) -ForegroundColor Yellow
                }
            }
        }

        default { throw "Неверный режим SchedulerMode: $SchedulerMode" }
    }

    # --- 8. Немедленный запуск BgInfo ---
    Start-Process -FilePath $bginfoExePath -ArgumentList "$configPath /timer:0 /NOLICPROMPT /silent"
    Write-Host "BgInfo запущен сразу после установки." -ForegroundColor Green

} catch {
    Write-Host ("Ошибка создания задачи в планировщике: " + $_) -ForegroundColor Red
}

# --- 9. Пауза для интерактивной проверки (закомментировано для автоматизации) ---
# Write-Host "`nНажмите любую клавишу для выхода..." -ForegroundColor Yellow
# $null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')
