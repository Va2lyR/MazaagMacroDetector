param(
  [switch]$NoPause,
  [switch]$Quick,
  [switch]$Deep,
  [switch]$ExcludePeripheral,
  [switch]$Export,
  [int]$MaxSeconds = 140
)

$ErrorActionPreference = 'SilentlyContinue'
$script:Findings = New-Object System.Collections.Generic.List[object]
$script:Now = Get-Date
$script:ToolRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$script:MaxFilesPerRoot = if ($Deep) { 4500 } elseif ($Quick) { 1000 } else { 2800 }
$script:ScanStartedAt = Get-Date
$script:MaxScanSeconds = if ($Deep) { [Math]::Max($MaxSeconds, 200) } elseif ($Quick) { [Math]::Min($MaxSeconds, 55) } else { $MaxSeconds }
$script:IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

function Test-TimeBudget { return (((Get-Date) - $script:ScanStartedAt).TotalSeconds -lt $script:MaxScanSeconds) }

function Write-Header {
  Clear-Host
  Write-Host "╔════════════════════════════════════════════════════════════════════════════════════╗" -ForegroundColor Red
  Write-Host "║" -ForegroundColor Red -NoNewline
  Write-Host "                 MAZAAG MACRO  v2                 " -ForegroundColor White -NoNewline
  Write-Host "║" -ForegroundColor Red
  Write-Host "╚════════════════════════════════════════════════════════════════════════════════════╝" -ForegroundColor Red
  Write-Host
  Write-Host "  ███╗   ███╗ █████╗ ███████╗ █████╗  █████╗  ██████╗ " -ForegroundColor Red
  Write-Host "  ████╗ ████║██╔══██╗╚══███╔╝██╔══██╗██╔══██╗██╔════╝ " -ForegroundColor Red
  Write-Host "  ██╔████╔██║███████║  ███╔╝ ███████║███████║██║  ███╗" -ForegroundColor Red
  Write-Host "  ██║╚██╔╝██║██╔══██║ ███╔╝  ██╔══██║██╔══██║██║   ██║" -ForegroundColor Red
  Write-Host "  ██║ ╚═╝ ██║██║  ██║███████╗██║  ██║██║  ██║╚██████╔╝" -ForegroundColor Red
  Write-Host "  ╚═╝     ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝ " -ForegroundColor Red
  Write-Host
  Write-Host "              HIGH-ACCURACY MACRO DETECTOR" -ForegroundColor Red
  Write-Host "         dev by ValyaR  |  discord: _iaec  .mazaag" -ForegroundColor DarkRed
  Write-Host ("═" * 84) -ForegroundColor Red
  Write-Host ("   Scan time : {0}" -f $script:Now.ToString('yyyy-MM-dd HH:mm:ss')) -ForegroundColor White
  Write-Host ("   Mode      : {0} | Admin: {1} | Budget: {2}s" -f $(if($Deep){'DEEP'}elseif($Quick){'QUICK'}else{'NORMAL'}), $script:IsAdmin, $script:MaxScanSeconds) -ForegroundColor White
  Write-Host ("═" * 84) -ForegroundColor Red
  Write-Host
}

function Write-BigResultsTitle {
  Write-Host
  Write-Host "  ██████╗ ███████╗███████╗██╗   ██╗██╗  ████████╗███████╗" -ForegroundColor Red
  Write-Host "  ██╔══██╗██╔════╝██╔════╝██║   ██║██║  ╚══██╔══╝██╔════╝" -ForegroundColor Red
  Write-Host "  ██████╔╝█████╗  ███████╗██║   ██║██║     ██║   ███████╗" -ForegroundColor Red
  Write-Host "  ██╔══██╗██╔══╝  ╚════██║██║   ██║██║     ██║   ╚════██║" -ForegroundColor Red
  Write-Host "  ██║  ██║███████╗███████║╚██████╔╝███████╗██║   ███████║" -ForegroundColor Red
  Write-Host "  ╚═╝  ╚═╝╚══════╝╚══════╝ ╚═════╝ ╚══════╝╚═╝   ╚══════╝" -ForegroundColor Red
  Write-Host
}

function Write-ProgressBar {
  param([int]$Percent, [string]$Status)
  $width = 42
  $filled = [math]::Floor(($Percent / 100) * $width)
  $bar = ('█' * $filled) + ('░' * ($width - $filled))
  Write-Host ("`r[ {0} ] {1,3}%  {2}" -f $bar, $Percent, $Status) -ForegroundColor Red -NoNewline
  if ($Percent -ge 100) { Write-Host }
}

function Get-SeverityRank { param([string]$S) switch($S){'HIGH'{0}'MEDIUM'{1}default{2}} }

function Test-MacroName {
  param([string]$Name)
  if ([string]::IsNullOrWhiteSpace($Name)) { return $false }
  $l = $Name.ToLowerInvariant()
  $p = @(
    'autohotkey','.ahk','autoit','.au3','tinytask','pulover','keyran','xmouse',
    'op auto','opauto','gs auto','gsauto','murgee','alphaclicker','speed auto',
    'free auto clicker','pymacro','minimouse','inseffra','jitbit','macro recorder',
    'autoclicker','auto clicker','auto-click','doubleclick','rapidfire','rapid-fire',
    'clicker','.mcr','.amc','.tinytask','.rec','interception'
  )
  foreach ($x in $p) { if ($l.Contains($x)) { return $true } }
  return $false
}

function Test-PeripheralSoftwareName {
  param([string]$Name)
  if ([string]::IsNullOrWhiteSpace($Name)) { return $false }
  $l = $Name.ToLowerInvariant()
  $p = @('steelseries','razer','synapse','logitech','lghub','g hub','corsair','icue','roccat','swarm','bloody','redragon','glorious','hyperx','ngenuity','armoury','asus','msi','cooler master','alienware','pulsar','lamzu','attackshark','x-mouse','xmouse')
  foreach ($x in $p) { if ($l.Contains($x)) { return $true } }
  return $false
}

function Test-OwnToolFile {
  param([string]$Path)
  if ([string]::IsNullOrWhiteSpace($Path)) { return $false }
  $n = [IO.Path]::GetFileName($Path)
  if ($n -match '^(Mazaag.?Macro|Macro Detector|MazaagtoolM)\.(cmd|ps1|zip)$') { return $true }
  if ($Path -match '\\(Mazaag.?Macro|Macro Detector)\\') { return $true }
  return $false
}

function Add-Finding {
  param(
    [ValidateSet('HIGH','MEDIUM','LOW')][string]$Severity,
    [string]$Category, [string]$Evidence, [string]$Path = '',
    [Nullable[datetime]]$UsedAt = $null, [Nullable[datetime]]$CreatedAt = $null,
    [Nullable[datetime]]$ModifiedAt = $null, [Nullable[datetime]]$DeletedAt = $null,
    [string]$Details = ''
  )
  $existing = $null
  if ($Path) {
    $existing = $script:Findings | Where-Object {
      $_.Path -and $_.Path.Equals($Path, [StringComparison]::OrdinalIgnoreCase) -and
      $_.Category -notlike 'Deleted*' -and $Category -notlike 'Deleted*'
    } | Select-Object -First 1
  }
  if ($existing) {
    if ((Get-SeverityRank $Severity) -lt (Get-SeverityRank $existing.Severity)) {
      $existing.Severity = $Severity; $existing.Category = $Category; $existing.Evidence = $Evidence
    }
    if ($UsedAt -and (-not $existing.UsedAt -or $UsedAt -gt $existing.UsedAt)) { $existing.UsedAt = $UsedAt }
    if ($CreatedAt -and (-not $existing.CreatedAt -or $CreatedAt -gt $existing.CreatedAt)) { $existing.CreatedAt = $CreatedAt }
    if ($ModifiedAt -and (-not $existing.ModifiedAt -or $ModifiedAt -gt $existing.ModifiedAt)) { $existing.ModifiedAt = $ModifiedAt }
    if ($DeletedAt -and (-not $existing.DeletedAt -or $DeletedAt -gt $existing.DeletedAt)) { $existing.DeletedAt = $DeletedAt }
    if ($Details -and $existing.Details -notlike "*$Details*") {
      $existing.Details = (($existing.Details, $Details) | Where-Object { $_ }) -join ' | '
    }
    return
  }
  $script:Findings.Add([pscustomobject]@{
    Severity=$Severity; Category=$Category; Evidence=$Evidence; UsedAt=$UsedAt
    CreatedAt=$CreatedAt; ModifiedAt=$ModifiedAt; DeletedAt=$DeletedAt; Path=$Path; Details=$Details
  }) | Out-Null
}

function Format-Time { param($V) if ($null -eq $V) { return '-' }; if ($V -is [datetime]) { return $V.ToString('yyyy-MM-dd HH:mm:ss') }; return '-' }

function Get-UserDirs {
  $dirs = New-Object System.Collections.Generic.List[string]
  $base = Join-Path $env:SystemDrive 'Users'
  Get-ChildItem -LiteralPath $base -Directory -Force | ForEach-Object {
    if ($_.Name -notin @('Default','Default User','All Users','Public')) { $dirs.Add($_.FullName) | Out-Null }
  }
  return $dirs
}

function Get-ScanRoots {
  $roots = New-Object System.Collections.Generic.List[object]
  $depth = if ($Deep) { 6 } elseif ($Quick) { 3 } else { 4 }
  foreach ($user in Get-UserDirs) {
    foreach ($sub in @('Desktop','Downloads','Documents')) {
      $p = Join-Path $user $sub
      if (Test-Path -LiteralPath $p) { $roots.Add([pscustomobject]@{Path=$p; Depth=$depth}) | Out-Null }
    }
    foreach ($sub in @(
      'AppData\Roaming\AutoHotkey','AppData\Roaming\Pulover','AppData\Roaming\TinyTask','AppData\Roaming\Keyran',
      'AppData\Roaming\XMouseButtonControl','AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup',
      'AppData\Local\AutoHotkey','AppData\Local\Pulover','AppData\Local\TinyTask','AppData\Local\Keyran',
      'AppData\Local\XMouseButtonControl','AppData\Local\Temp'
    )) {
      $p = Join-Path $user $sub
      if (Test-Path -LiteralPath $p) { $roots.Add([pscustomobject]@{Path=$p; Depth=5}) | Out-Null }
    }
  }
  return $roots | Sort-Object Path -Unique
}

function Test-SkipScanPath {
  param([string]$Path)
  if ([string]::IsNullOrWhiteSpace($Path)) { return $true }
  return $Path -match '\\(node_modules|\.git|\.cache|cache|temp|tmp|logs|shaderpacks|resourcepacks|versions|libraries|assets|screenshots|crash-reports|Medal|resource.?pack)(\\|$)'
}

function Get-PeripheralVendor {
  param([string]$Name)
  $l = $Name.ToLowerInvariant()
  if ($l -match 'steelseries') { return 'SteelSeries' }
  if ($l -match 'razer|synapse') { return 'Razer' }
  if ($l -match 'logitech|lghub|g hub') { return 'Logitech' }
  if ($l -match 'corsair|icue') { return 'Corsair' }
  if ($l -match 'roccat|swarm') { return 'ROCCAT' }
  if ($l -match 'bloody') { return 'Bloody' }
  if ($l -match 'redragon') { return 'Redragon' }
  if ($l -match 'glorious') { return 'Glorious' }
  if ($l -match 'hyperx') { return 'HyperX' }
  if ($l -match 'asus|armoury') { return 'ASUS' }
  if ($l -match 'x-mouse|xmouse') { return 'X-Mouse Button Control' }
  return 'Peripheral software'
}

function Search-KnownMacroProcesses {
  $names = @(
    'AutoHotkey','AutoHotkeyU32','AutoHotkeyU64','AutoHotkey32','AutoHotkey64',
    'AutoIt3','AutoIt','Pulover','PuloversMacroCreator','MacroRecorder','JitbitMacroRecorder',
    'TinyTask','MiniMouseMacro','MouseRecorder','Keyran','XMouseButtonControl','Interception',
    'OPAutoClicker','OP Auto Clicker','GSAutoClicker','GS Auto Clicker','Murgee','AlphaClicker',
    'SpeedAutoClicker','FreeAutoClicker','PyMacroRecord','Inseffra'
  )
  Get-CimInstance Win32_Process | ForEach-Object {
    $n = $_.Name; $c = $_.CommandLine; $match = $false
    foreach ($k in $names) { if ($n -like "*$k*" -or $c -like "*$k*") { $match = $true; break } }
    if ($match -or $c -match '\.(ahk|au3)(\s|$|")') {
      $started = $null
      if ($_.CreationDate) { $started = [Management.ManagementDateTimeConverter]::ToDateTime($_.CreationDate) }
      Add-Finding -Severity 'HIGH' -Category 'Running macro process' -Evidence $n -Path $_.ExecutablePath -UsedAt $started -Details ($c -replace '\s+',' ')
    }
  }
}

function Search-StartupTasksServices {
  foreach ($user in Get-UserDirs) {
    $startup = Join-Path $user 'AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup'
    if (Test-Path $startup) {
      Get-ChildItem $startup -Force -File -EA SilentlyContinue | ForEach-Object {
        if (Test-MacroName $_.Name) {
          Add-Finding -Severity 'HIGH' -Category 'Startup entry' -Evidence $_.Name -Path $_.FullName -CreatedAt $_.CreationTime -ModifiedAt $_.LastWriteTime -Details 'User Startup folder'
        }
      }
    }
  }
  $common = "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
  if (Test-Path $common) {
    Get-ChildItem $common -Force -File -EA SilentlyContinue | ForEach-Object {
      if (Test-MacroName $_.Name) {
        Add-Finding -Severity 'HIGH' -Category 'Startup entry' -Evidence $_.Name -Path $_.FullName -Details 'All Users Startup'
      }
    }
  }
  try {
    Get-ScheduledTask | Where-Object State -ne 'Disabled' | ForEach-Object {
      $acts = ($_.Actions | ForEach-Object { $_.Execute + ' ' + $_.Arguments }) -join ' '
      $txt = $_.TaskName + ' ' + $acts
      if (Test-MacroName $txt -or $txt -match '\.(ahk|au3)') {
        Add-Finding -Severity 'HIGH' -Category 'Scheduled Task' -Evidence $_.TaskName -Path $_.TaskPath -Details $acts
      }
    }
  } catch {}
}

function Search-BAM {
  $bamPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings'
  if (-not (Test-Path $bamPath)) { return }
  Get-ChildItem $bamPath -EA SilentlyContinue | ForEach-Object {
    $sid = $_.PSChildName
    Get-ItemProperty $_.PSPath -EA SilentlyContinue | ForEach-Object {
      $_.PSObject.Properties | Where-Object { $_.Name -match '\\Device\\' -or $_.Name -match ':[\\]' } | ForEach-Object {
        $path = $_.Name
        if (Test-MacroName $path) {
          $ts = $null
          try {
            if ($_.Value -is [byte[]] -and $_.Value.Length -ge 8) {
              $filetime = [BitConverter]::ToInt64($_.Value, 0)
              $ts = [DateTime]::FromFileTimeUtc($filetime).ToLocalTime()
            }
          } catch {}
          Add-Finding -Severity 'HIGH' -Category 'BAM execution trace' -Evidence ([IO.Path]::GetFileName($path)) -Path $path -UsedAt $ts -Details "BAM SID: $sid"
        }
      }
    }
  }
}

function Search-Event4688 {
  if (-not $script:IsAdmin) { return }
  try {
    $events = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4688; StartTime=(Get-Date).AddDays(-2)} -MaxEvents 600 -EA SilentlyContinue
    foreach ($e in $events) {
      $msg = $e.Message
      if ($msg -match '(?i)(AutoHotkey|AutoIt3|TinyTask|Pulover|Keyran|XMouse|OPAutoClicker|GSAutoClicker|Murgee|AlphaClicker|\.ahk|\.au3)') {
        $proc = if ($msg -match 'New Process Name:\s*(.+)') { $Matches[1].Trim() } else { 'Unknown' }
        Add-Finding -Severity 'HIGH' -Category 'Event 4688 process creation' -Evidence $proc -UsedAt $e.TimeCreated -Details 'Security log'
      }
    }
  } catch {}
}

function Search-FilterDrivers {
  Get-CimInstance Win32_SystemDriver | Where-Object { $_.State -eq 'Running' } | ForEach-Object {
    $n = $_.Name + ' ' + $_.PathName
    if ($n -match '(?i)interception') {
      Add-Finding -Severity 'HIGH' -Category 'Input filter driver' -Evidence $_.Name -Path $_.PathName -Details 'Interception driver detected'
    }
  }
}

function Search-PeripheralSoftware {
  if ($ExcludePeripheral) { return }
  $running = @{}
  Get-CimInstance Win32_Process | ForEach-Object {
    $n = $_.Name; $c = $_.CommandLine; $p = $_.ExecutablePath
    if (Test-PeripheralSoftwareName "$n $c $p") {
      $started = $null
      if ($_.CreationDate) { $started = [Management.ManagementDateTimeConverter]::ToDateTime($_.CreationDate) }
      $v = Get-PeripheralVendor "$n $c $p"
      if (-not $running.ContainsKey($v)) { $running[$v] = [pscustomobject]@{Vendor=$v; Started=$started; Path=$p; Count=0} }
      $running[$v].Count++
      if ($started -and (-not $running[$v].Started -or $started -gt $running[$v].Started)) {
        $running[$v].Started = $started; $running[$v].Path = $p
      }
    }
  }
  foreach ($v in $running.Keys) {
    $e = $running[$v]
    Add-Finding -Severity 'MEDIUM' -Category 'Peripheral software running' -Evidence $e.Vendor -Path $e.Path -UsedAt $e.Started -Details "Processes: $($e.Count)"
  }
}

function Search-MacroFiles {
  $allowed = @('.ahk','.au3','.exe','.mcr','.amc','.rec','.tinytask')
  foreach ($root in Get-ScanRoots) {
    if (-not (Test-TimeBudget)) { break }
    Get-ChildItem -LiteralPath $root.Path -Recurse -Depth $root.Depth -Force -File -EA SilentlyContinue |
      Where-Object { -not (Test-SkipScanPath $_.FullName) } |
      Select-Object -First $script:MaxFilesPerRoot |
      ForEach-Object {
        if (-not (Test-TimeBudget)) { return }
        if ($_.Length -gt 25MB) { return }
        if (Test-OwnToolFile $_.FullName) { return }
        if ($_.Extension -and ($allowed -notcontains $_.Extension.ToLowerInvariant())) { return }
        if (-not (Test-MacroName $_.Name)) { return }

        $sev = if ($_.Extension -match '\.(ahk|au3)' -or $_.Name -match '(?i)autohotkey|autoit|tinytask|pulover|op.?auto|gs.?auto|clicker|macro') { 'MEDIUM' } else { 'LOW' }
        Add-Finding -Severity $sev -Category 'Macro-related file' -Evidence $_.Name -Path $_.FullName -CreatedAt $_.CreationTime -ModifiedAt $_.LastWriteTime -Details ("Size: {0} KB" -f [math]::Round($_.Length/1KB,1))
      }
  }
}

function Search-AhkScriptContent {
  $weights = @{
    'SendInput'=3; 'SendEvent'=3; 'Click'=4; 'MouseClick'=4; 'Loop'=2; 'SetTimer'=2
    'Hotkey'=1; 'GetKeyState'=1; '~LButton'=3; '~RButton'=3; 'XButton1'=3; 'XButton2'=3
    'Send'=2; 'Sleep'=1; 'PixelSearch'=3; 'ImageSearch'=3
  }

  foreach ($root in Get-ScanRoots) {
    if (-not (Test-TimeBudget)) { break }

    Get-ChildItem -LiteralPath $root.Path -Recurse -Depth $root.Depth -Force -File -Include *.ahk,*.au3 -ErrorAction SilentlyContinue |
      Where-Object {
        -not (Test-SkipScanPath $_.FullName) -and
        $_.Length -le 2MB -and
        $_.Extension -match '\.(ahk|au3)$'
      } |
      Select-Object -First 300 |
      ForEach-Object {
        if (-not (Test-TimeBudget)) { return }

        $content = Get-Content -LiteralPath $_.FullName -Raw -ErrorAction SilentlyContinue
        if (-not $content) { return }

        $score = 0
        $hits = @()
        foreach ($k in $weights.Keys) {
          if ($content -match [regex]::Escape($k)) {
            $score += $weights[$k]
            $hits += $k
          }
        }

        if ($content -match 'Sleep\s*,\s*\d{1,2}\b') { $score += 4; $hits += 'VeryShortSleep' }
        if ($content -match 'Loop\s*,\s*\d{2,}') { $score += 3; $hits += 'HighLoop' }

        if ($score -lt 6) { return }

        $sev = if ($score -ge 11) { 'HIGH' } else { 'MEDIUM' }

        Add-Finding -Severity $sev -Category 'Script content evidence' -Evidence $_.Name -Path $_.FullName `
          -CreatedAt $_.CreationTime -ModifiedAt $_.LastWriteTime `
          -Details ("Score:$score | " + (($hits | Select-Object -Unique) -join ','))
      }
  }
}

function Search-DeletedMacros {
  $cutoff = (Get-Date).AddDays(-2)
  $drives = Get-PSDrive -PSProvider FileSystem | Where-Object { $_.Root -match '^[A-Z]:\\$' } | Select-Object -First 3
  foreach ($d in $drives) {
    if (-not (Test-TimeBudget)) { break }
    $bin = Join-Path $d.Root '$Recycle.Bin'
    if (-not (Test-Path $bin)) { continue }
    Get-ChildItem $bin -Recurse -Force -File -Filter '$I*' -EA SilentlyContinue |
      Where-Object LastWriteTime -ge $cutoff |
      Sort-Object LastWriteTime -Descending | Select-Object -First 800 |
      ForEach-Object {
        if (-not (Test-TimeBudget)) { return }
        try {
          $bytes = [IO.File]::ReadAllBytes($_.FullName)
          if ($bytes.Length -lt 26) { return }
          $ft = [BitConverter]::ToInt64($bytes, 16)
          if ($ft -le 0) { return }
          $del = [DateTime]::FromFileTimeUtc($ft).ToLocalTime()
          if ($del -lt $cutoff) { return }
          $raw = [Text.Encoding]::Unicode.GetString($bytes, 24, $bytes.Length - 24).Trim([char]0)
          $name = [IO.Path]::GetFileName($raw)
          if (Test-OwnToolFile $raw) { return }
          if (Test-MacroName $name -or Test-MacroName $raw) {
            Add-Finding -Severity 'MEDIUM' -Category 'Deleted macro trace' -Evidence $name -Path $raw -DeletedAt $del -Details 'Recycle Bin (last 48h)'
          }
        } catch {}
      }
  }
}

function Search-Prefetch {
  $pf = Join-Path $env:SystemRoot 'Prefetch'
  if (-not (Test-Path $pf)) { return }
  $patterns = @('*AUTOHOTKEY*','*AUTOIT*','*TINYTASK*','*OPAUTO*','*GSAUTO*','*MURGEE*','*ALPHACLICK*','*CLICKER*','*PULOVER*','*KEYRAN*','*XMOUSE*','*JITBIT*','*INTERCEPT*')
  foreach ($pat in $patterns) {
    Get-ChildItem $pf -Filter "$pat.pf" -File -Force -EA SilentlyContinue | ForEach-Object {
      Add-Finding -Severity 'HIGH' -Category 'Prefetch execution' -Evidence $_.Name -Path $_.FullName -UsedAt $_.LastWriteTime -ModifiedAt $_.LastWriteTime -Details 'Prefetch proves execution'
    }
  }
}

function Search-RecentJavaLogs {
  foreach ($user in Get-UserDirs) {
    $log = Join-Path $user 'AppData\Roaming\.minecraft\logs'
    if (-not (Test-Path $log)) { continue }
    Get-ChildItem $log -File -Filter '*.log' -EA SilentlyContinue |
      Sort-Object LastWriteTime -Descending | Select-Object -First 3 |
      ForEach-Object {
        $c = Get-Content $_.FullName -Raw -EA SilentlyContinue
        if ($c -match '(?i)(autohotkey|autoit|tinytask|op.?auto|gs.?auto|murgee|alphaclicker|keyran|xmouse)') {
          Add-Finding -Severity 'MEDIUM' -Category 'Minecraft log hit' -Evidence $_.Name -Path $_.FullName -ModifiedAt $_.LastWriteTime -Details 'Keyword in recent MC log'
        }
      }
  }
}

function Write-CleanSummary {
  $high = @($script:Findings | Where-Object Severity -eq 'HIGH').Count
  $med  = @($script:Findings | Where-Object Severity -eq 'MEDIUM').Count
  $low  = @($script:Findings | Where-Object Severity -eq 'LOW').Count
  $del  = @($script:Findings | Where-Object DeletedAt).Count
  $status = if ($high -gt 0) { 'DIRECT EVIDENCE FOUND - Review HIGH first' }
            elseif ($med -gt 0) { 'Strong traces found - Review MEDIUM' }
            elseif ($low -gt 0) { 'Only weak context found' }
            else { 'No strict macro evidence found' }
  Write-Host 'Clean summary' -ForegroundColor Cyan
  Write-Host ("    Verdict              : {0}" -f $status)
  Write-Host ("    Levels               : HIGH={0}  MEDIUM={1}  LOW={2}" -f $high,$med,$low)
  Write-Host ("    Deleted (48h)        : {0}" -f $del)
  Write-Host
}

function Write-FindingTable {
  $ordered = $script:Findings | ForEach-Object {
    $r = Get-SeverityRank $_.Severity
    $s = @($_.DeletedAt,$_.UsedAt,$_.CreatedAt,$_.ModifiedAt) | Where-Object { $_ -is [datetime] } | Sort-Object -Descending | Select-Object -First 1
    $_ | Add-Member Rank $r -Force; $_ | Add-Member SignalAt $s -Force; $_
  } | Sort-Object Rank, Category, @{E='SignalAt'; Descending=$true}

  if (-not $ordered -or $ordered.Count -eq 0) {
    Write-Host 'No strict macro evidence was found.' -ForegroundColor Green
    Write-Host 'This does not prove macros were never used.' -ForegroundColor DarkGray
    return
  }

  $i=1; $last=''
  foreach ($f in $ordered) {
    if (-not $last) {
      if ($f.Severity -eq 'HIGH') { Write-Host ('█'*80) -ForegroundColor Red; Write-Host '                                   HIGH' -ForegroundColor Red; Write-Host ('█'*80) -ForegroundColor Red }
      elseif ($f.Severity -eq 'MEDIUM') { Write-Host ('█'*80) -ForegroundColor Yellow; Write-Host '                                  MEDIUM' -ForegroundColor Yellow; Write-Host ('█'*80) -ForegroundColor Yellow }
      else { Write-Host ('-'*80) -ForegroundColor DarkGray; Write-Host '                                    LOW' -ForegroundColor Gray; Write-Host ('-'*80) -ForegroundColor DarkGray }
    } elseif ($last -eq 'HIGH' -and $f.Severity -eq 'MEDIUM') {
      Write-Host ('█'*80) -ForegroundColor Yellow; Write-Host '                                  MEDIUM' -ForegroundColor Yellow; Write-Host ('█'*80) -ForegroundColor Yellow
    } elseif ($last -eq 'MEDIUM' -and $f.Severity -eq 'LOW') {
      Write-Host ('-'*80) -ForegroundColor DarkGray; Write-Host '                                    LOW' -ForegroundColor Gray; Write-Host ('-'*80) -ForegroundColor DarkGray
    }
    $last = $f.Severity
    $col = switch($f.Severity){'HIGH'{'Red'}'MEDIUM'{'Yellow'}default{'Gray'}}
    Write-Host ("[{0}] {1} | {2}" -f $i,$f.Severity,$f.Category) -ForegroundColor $col
    Write-Host ("    Evidence : {0}" -f $f.Evidence)
    Write-Host ("    Used at  : {0}" -f (Format-Time $f.UsedAt))
    Write-Host ("    Created  : {0}" -f (Format-Time $f.CreatedAt))
    Write-Host ("    Modified : {0}" -f (Format-Time $f.ModifiedAt))
    Write-Host ("    Deleted  : {0}" -f (Format-Time $f.DeletedAt))
    if ($f.Path) { Write-Host ("    Path     : {0}" -f $f.Path) }
    if ($f.Details) { Write-Host ("    Details  : {0}" -f $f.Details) }
    Write-Host; $i++
  }
}

function Export-Results {
  if (-not $Export) { return }
  $stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
  $json = Join-Path $script:ToolRoot "MazaagMacro_$stamp.json"
  $html = Join-Path $script:ToolRoot "MazaagMacro_$stamp.html"
  $script:Findings | ConvertTo-Json -Depth 5 | Set-Content $json -Encoding UTF8
  $h = @"
<!DOCTYPE html><html><head><meta charset="utf-8"><title>Mazaag Macro v2</title>
<style>body{font-family:Consolas,monospace;background:#0a0a0a;color:#eee;padding:24px}
h1{color:#ff1a3c} .high{color:#ff1a3c} .medium{color:#ffaa00} .low{color:#888}
table{border-collapse:collapse;width:100%} th,td{border:1px solid #333;padding:8px;text-align:left}
th{background:#1a1a1a}</style></head><body>
<h1>Mazaag Macro v2 Report</h1><p>Scan: $($script:Now.ToString('yyyy-MM-dd HH:mm:ss'))</p>
<table><tr><th>#</th><th>Severity</th><th>Category</th><th>Evidence</th><th>Path</th><th>Details</th></tr>
"@
  $n=1
  foreach ($f in ($script:Findings | Sort-Object {Get-SeverityRank $_.Severity})) {
    $h += "<tr class='$($f.Severity.ToLower())'><td>$n</td><td>$($f.Severity)</td><td>$($f.Category)</td><td>$($f.Evidence)</td><td>$($f.Path)</td><td>$($f.Details)</td></tr>`n"
    $n++
  }
  $h += "</table></body></html>"
  $h | Set-Content $html -Encoding UTF8
  Write-Host; Write-Host "Exported:" -ForegroundColor Cyan
  Write-Host "  JSON : $json"; Write-Host "  HTML : $html"
}

Write-Header
Write-ProgressBar 0 'Starting scan'

Search-KnownMacroProcesses;     Write-ProgressBar 12 'Processes'
Search-StartupTasksServices;    Write-ProgressBar 22 'Startup/Tasks'
Search-BAM;                     Write-ProgressBar 32 'BAM'
Search-Event4688;               Write-ProgressBar 42 'Event 4688'
Search-FilterDrivers;           Write-ProgressBar 50 'Filter drivers'
Search-PeripheralSoftware;      Write-ProgressBar 58 'Peripherals'
Search-MacroFiles;              Write-ProgressBar 70 'Macro files'
Search-AhkScriptContent;        Write-ProgressBar 82 'Script content'
Search-DeletedMacros;           Write-ProgressBar 90 'Deleted traces'
Search-Prefetch;                Write-ProgressBar 96 'Prefetch'
Search-RecentJavaLogs;          Write-ProgressBar 100 'Complete'

Write-Host; Write-BigResultsTitle
Write-Host ('='*86) -ForegroundColor Red
Write-CleanSummary
Write-FindingTable
Export-Results
Write-Host ('='*86) -ForegroundColor Red
Write-Host 'HIGH = direct proof. MEDIUM = strong trace. LOW = weak context only.' -ForegroundColor DarkGray
Write-Host 'Run as Admin for best coverage.' -ForegroundColor DarkGray
if (-not (Test-TimeBudget)) { Write-Host 'Time budget reached.' -ForegroundColor Yellow }
if (-not $NoPause) { Write-Host; Read-Host 'Press Enter to exit' | Out-Null }

$h = @($script:Findings | Where-Object Severity -eq 'HIGH').Count
$m = @($script:Findings | Where-Object Severity -eq 'MEDIUM').Count
if ($h -gt 0) { exit 2 }
if ($m -gt 0) { exit 1 }
exit 0
