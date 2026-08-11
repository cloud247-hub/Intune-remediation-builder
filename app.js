'use strict';

const $ = (id) => document.getElementById(id);
const encoder = new TextEncoder();

const state = {
  selectedRecipeId: 'defender',
  recipeValues: {},
  testValues: {},
  packageName: 'Kontroller Microsoft Defender',
  detection: '',
  remediation: '',
  configDirty: false,
  scriptDirty: false,
  toastTimer: null
};

const scheduleLabels = {
  daily: 'Daglig',
  hourly: 'Hver 8. time',
  weekly: 'Ukentlig',
  once: 'Én gang'
};

function singleLine(value) {
  return String(value ?? '').replace(/[\r\n\t]+/g, ' ').replace(/\s{2,}/g, ' ').trim();
}

function commentText(value) {
  return singleLine(value).replace(/<#/g, '< #').replace(/#>/g, '# >');
}

function psString(value) {
  return `'${singleLine(value).replace(/'/g, "''")}'`;
}

function clampNumber(value, min, max, fallback) {
  const number = Number(value);
  if (!Number.isFinite(number)) return fallback;
  return Math.min(max, Math.max(min, number));
}

function sanitizeFilePart(value) {
  return String(value || 'Intune-Remediation')
    .normalize('NFKD')
    .replace(/[\u0300-\u036f]/g, '')
    .replace(/[^a-z0-9._-]+/gi, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 80) || 'Intune-Remediation';
}

function formatBytes(bytes) {
  if (bytes < 1024) return `${bytes} byte`;
  return `${(bytes / 1024).toFixed(bytes < 10240 ? 1 : 0)} KB`;
}

function currentRecipe() {
  return recipes.find((recipe) => recipe.id === state.selectedRecipeId) || recipes[0];
}

function getMeta() {
  return {
    packageName: state.packageName.trim() || currentRecipe().defaultPackage,
    runAsUser: $('runAsUser').value === 'yes',
    run64Bit: $('run64Bit').value === 'yes',
    signatureCheck: $('signatureCheck').value === 'yes',
    schedule: $('schedule').value,
    generatedAt: new Date()
  };
}

function scriptHeader(kind, recipe, meta, purpose) {
  const context = meta.runAsUser ? 'Pålogget brukerkontekst' : 'SYSTEM-kontekst';
  return [
    '#requires -Version 5.1',
    '<#',
    '.SYNOPSIS',
    `    ${kind === 'detection' ? 'Detection' : 'Remediation'} for ${recipe.name}.`,
    '.DESCRIPTION',
    `    ${commentText(purpose)}`,
    '.NOTES',
    `    Pakke: ${commentText(meta.packageName)}`,
    `    Oppskrift: ${recipe.name}`,
    `    Kjøringskontekst: ${context}`,
    '    Generert av Intune Remediation Builder.',
    '    Test alltid på en avgrenset enhetsgruppe før produksjon.',
    '#>',
    '',
    "$ErrorActionPreference = 'Stop'"
  ].join('\n');
}

function bitLockerGenerator(params, meta, recipe) {
  const method = ['XtsAes128', 'XtsAes256'].includes(params.encryptionMethod) ? params.encryptionMethod : 'XtsAes256';
  const safeOnly = params.bitlockerAction !== 'enable';
  const usedSpaceOnly = params.usedSpaceOnly ? ' -UsedSpaceOnly' : '';
  const detection = [
    scriptHeader('detection', recipe, meta, 'Kontrollerer at operativsystemvolumet er fullstendig kryptert og at BitLocker-beskyttelsen er aktiv.'),
    '',
    'try {',
    '    $volume = Get-BitLockerVolume -MountPoint $env:SystemDrive',
    "    $isEncrypted = $volume.VolumeStatus -eq 'FullyEncrypted'",
    "    $isProtected = $volume.ProtectionStatus -eq 'On'",
    '',
    '    if ($isEncrypted -and $isProtected) {',
    '        Write-Output "OK: BitLocker er fullstendig kryptert og beskyttelsen er aktiv på $env:SystemDrive."',
    '        exit 0',
    '    }',
    '',
    '    Write-Output ("AVVIK: VolumeStatus={0}; ProtectionStatus={1}." -f $volume.VolumeStatus, $volume.ProtectionStatus)',
    '    exit 1',
    '}',
    'catch {',
    '    Write-Output ("AVVIK: Klarte ikke å lese BitLocker-status: {0}" -f $_.Exception.Message)',
    '    exit 1',
    '}'
  ].join('\n');

  const remediationLines = [
    scriptHeader('remediation', recipe, meta, safeOnly
      ? 'Gjenopptar BitLocker-beskyttelse dersom volumet allerede er kryptert. Starter ikke ny kryptering.'
      : 'Aktiverer eller gjenopptar BitLocker på operativsystemvolumet og forsøker å sikre en gjenopprettingsnøkkel.'),
    '',
    'try {',
    '    $volume = Get-BitLockerVolume -MountPoint $env:SystemDrive',
    '',
    "    if ($volume.VolumeStatus -eq 'FullyEncrypted' -and $volume.ProtectionStatus -eq 'On') {",
    '        Write-Output "OK: BitLocker krever ingen retting."',
    '        exit 0',
    '    }',
    '',
    "    if ($volume.VolumeStatus -eq 'FullyEncrypted' -and $volume.ProtectionStatus -ne 'On') {",
    '        Resume-BitLocker -MountPoint $env:SystemDrive',
    '        Write-Output "RETTET: BitLocker-beskyttelsen ble gjenopptatt."',
    '        exit 0',
    '    }'
  ];

  if (safeOnly) {
    remediationLines.push(
      '',
      '    Write-Output "MANUELL HANDLING: Volumet er ikke fullstendig kryptert. Denne sikre malen starter ikke ny kryptering."',
      '    exit 1'
    );
  } else {
    remediationLines.push(
      '',
      "    if ($volume.VolumeStatus -eq 'FullyDecrypted') {",
      '        $tpm = Get-Tpm',
      '        if (-not $tpm.TpmPresent -or -not $tpm.TpmReady) {',
      '            throw "TPM er ikke tilgjengelig eller klar."',
      '        }',
      '',
      `        Enable-BitLocker -MountPoint $env:SystemDrive -EncryptionMethod ${method} -TpmProtector${usedSpaceOnly} -SkipHardwareTest`,
      '        $recovery = Add-BitLockerKeyProtector -MountPoint $env:SystemDrive -RecoveryPasswordProtector',
    );
    if (params.backupAad) {
      remediationLines.push(
        '        if (Get-Command BackupToAAD-BitLockerKeyProtector -ErrorAction SilentlyContinue) {',
        '            try {',
        '                BackupToAAD-BitLockerKeyProtector -MountPoint $env:SystemDrive -KeyProtectorId $recovery.KeyProtector.KeyProtectorId',
        '            }',
        '            catch {',
        '                Write-Output ("ADVARSEL: Kryptering startet, men nøkkelen kunne ikke sikkerhetskopieres til Entra ID: {0}" -f $_.Exception.Message)',
        '            }',
        '        }'
      );
    }
    remediationLines.push(
      '        Write-Output "RETTET: BitLocker-kryptering er startet. Kontroller nøkkelbeskyttelse og escrow i Intune."',
      '        exit 0',
      '    }',
      '',
      '    Resume-BitLocker -MountPoint $env:SystemDrive -ErrorAction SilentlyContinue',
      '    Write-Output ("RETTET: BitLocker ble gjenopptatt. Nåværende status: {0}." -f $volume.VolumeStatus)',
      '    exit 0'
    );
  }

  remediationLines.push(
    '}',
    'catch {',
    '    Write-Output ("FEIL: BitLocker kunne ikke rettes: {0}" -f $_.Exception.Message)',
    '    exit 1',
    '}'
  );

  return { detection, remediation: remediationLines.join('\n') };
}

function oneDriveGenerator(params, meta, recipe) {
  const startupArgs = params.startupArgs || '/background';
  const detection = [
    scriptHeader('detection', recipe, meta, 'Kontrollerer at OneDrive-klienten er installert og kjører i den påloggede brukerens kontekst.'),
    '',
    'try {',
    '    $oneDrivePaths = @(',
    '        "$env:LOCALAPPDATA\\Microsoft\\OneDrive\\OneDrive.exe",',
    '        "$env:ProgramFiles\\Microsoft OneDrive\\OneDrive.exe",',
    '        "${env:ProgramFiles(x86)}\\Microsoft OneDrive\\OneDrive.exe"',
    '    ) | Where-Object { $_ -and (Test-Path $_) }',
    '',
    '    if (-not $oneDrivePaths) {',
    '        Write-Output "AVVIK: OneDrive.exe ble ikke funnet."',
    '        exit 1',
    '    }',
    '',
    "    $process = Get-Process -Name 'OneDrive' -ErrorAction SilentlyContinue",
    '    if ($process) {',
    '        Write-Output "OK: OneDrive-klienten kjører."',
    '        exit 0',
    '    }',
    '',
    '    Write-Output "AVVIK: OneDrive er installert, men prosessen kjører ikke."',
    '    exit 1',
    '}',
    'catch {',
    '    Write-Output ("AVVIK: OneDrive kunne ikke kontrolleres: {0}" -f $_.Exception.Message)',
    '    exit 1',
    '}'
  ].join('\n');

  const remediation = [
    scriptHeader('remediation', recipe, meta, 'Starter OneDrive-klienten i den påloggede brukerens kontekst dersom den er installert, men ikke kjører.'),
    '',
    'try {',
    '    $oneDrivePaths = @(',
    '        "$env:LOCALAPPDATA\\Microsoft\\OneDrive\\OneDrive.exe",',
    '        "$env:ProgramFiles\\Microsoft OneDrive\\OneDrive.exe",',
    '        "${env:ProgramFiles(x86)}\\Microsoft OneDrive\\OneDrive.exe"',
    '    ) | Where-Object { $_ -and (Test-Path $_) }',
    '',
    '    $oneDriveExe = $oneDrivePaths | Select-Object -First 1',
    '    if (-not $oneDriveExe) {',
    '        throw "OneDrive.exe ble ikke funnet. Distribuer klienten før denne remedieringen brukes."',
    '    }',
    '',
    "    if (-not (Get-Process -Name 'OneDrive' -ErrorAction SilentlyContinue)) {",
    `        Start-Process -FilePath $oneDriveExe -ArgumentList ${psString(startupArgs)} -WindowStyle Hidden`,
    '        Start-Sleep -Seconds 5',
    '    }',
    '',
    "    if (Get-Process -Name 'OneDrive' -ErrorAction SilentlyContinue) {",
    '        Write-Output "RETTET: OneDrive-klienten kjører."',
    '        exit 0',
    '    }',
    '',
    '    Write-Output "FEIL: OneDrive ble startet, men prosessen ble ikke funnet etterpå."',
    '    exit 1',
    '}',
    'catch {',
    '    Write-Output ("FEIL: OneDrive kunne ikke startes: {0}" -f $_.Exception.Message)',
    '    exit 1',
    '}'
  ].join('\n');

  return { detection, remediation };
}

function windowsUpdateGenerator(params, meta, recipe) {
  const triggerScan = Boolean(params.triggerScan);
  const detection = [
    scriptHeader('detection', recipe, meta, 'Kontrollerer at sentrale Windows Update-tjenester finnes og ikke er deaktivert.'),
    '',
    "$serviceNames = @('wuauserv', 'bits', 'UsoSvc')",
    '$problems = @()',
    '',
    'foreach ($serviceName in $serviceNames) {',
    '    $service = Get-CimInstance -ClassName Win32_Service -Filter "Name=\'$serviceName\'" -ErrorAction SilentlyContinue',
    '    if (-not $service) {',
    '        $problems += "$serviceName mangler"',
    '        continue',
    '    }',
    "    if ($service.StartMode -eq 'Disabled') {",
    '        $problems += "$serviceName er deaktivert"',
    '    }',
    '}',
    '',
    'if ($problems.Count -eq 0) {',
    '    Write-Output "OK: Windows Update-tjenestene er tilgjengelige og ikke deaktivert."',
    '    exit 0',
    '}',
    '',
    'Write-Output ("AVVIK: {0}" -f ($problems -join "; "))',
    'exit 1'
  ].join('\n');

  const remediationLines = [
    scriptHeader('remediation', recipe, meta, 'Aktiverer deaktiverte Windows Update-tjenester, starter nødvendige tjenester og kan starte et oppdateringssøk.'),
    '',
    '$problems = @()',
    '$changes = @()',
    '',
    "foreach ($serviceName in @('wuauserv', 'bits', 'UsoSvc')) {",
    '    $service = Get-CimInstance -ClassName Win32_Service -Filter "Name=\'$serviceName\'" -ErrorAction SilentlyContinue',
    '    if (-not $service) {',
    '        $problems += "$serviceName mangler"',
    '        continue',
    '    }',
    "    if ($service.StartMode -eq 'Disabled') {",
    '        try {',
    '            Set-Service -Name $serviceName -StartupType Manual -ErrorAction Stop',
    '            $changes += "$serviceName satt til Manual"',
    '        }',
    '        catch {',
    '            $problems += "$serviceName kunne ikke aktiveres"',
    '        }',
    '    }',
    '}',
    '',
    "foreach ($serviceName in @('bits', 'wuauserv')) {",
    '    try {',
    '        $service = Get-Service -Name $serviceName -ErrorAction Stop',
    "        if ($service.Status -ne 'Running') {",
    '            Start-Service -Name $serviceName -ErrorAction Stop',
    '            $changes += "$serviceName startet"',
    '        }',
    '    }',
    '    catch {',
    '        $problems += "$serviceName kunne ikke startes"',
    '    }',
    '}'
  ];
  if (triggerScan) {
    remediationLines.push(
      '',
      "try {",
      "    $usoClient = Join-Path $env:SystemRoot 'System32\\UsoClient.exe'",
      '    if (Test-Path $usoClient) {',
      "        Start-Process -FilePath $usoClient -ArgumentList 'StartScan' -WindowStyle Hidden -ErrorAction Stop",
      "        $changes += 'oppdateringssøk startet'",
      '    }',
      '}',
      'catch {',
      "    $problems += 'oppdateringssøk kunne ikke startes'",
      '}'
    );
  }
  remediationLines.push(
    '',
    'if ($problems.Count -gt 0) {',
    '    Write-Output ("FEIL: {0}. Endringer: {1}." -f ($problems -join "; "), ($changes -join "; "))',
    '    exit 1',
    '}',
    '',
    'Write-Output ("RETTET: Windows Update er kontrollert. Endringer: {0}." -f (($changes -join "; ") -replace "^$", "ingen nødvendige"))',
    'exit 0'
  );

  return { detection, remediation: remediationLines.join('\n') };
}

function printerGenerator(params, meta, recipe) {
  const staleMinutes = clampNumber(params.staleMinutes, 5, 1440, 60);
  const clearStale = Boolean(params.clearStaleJobs);
  const detectionLines = [
    scriptHeader('detection', recipe, meta, 'Kontrollerer at Print Spooler kjører og kan oppdage gamle filer i utskriftskøen.'),
    '',
    "try {",
    "    $service = Get-Service -Name 'Spooler' -ErrorAction Stop",
    "    $serviceConfig = Get-CimInstance -ClassName Win32_Service -Filter \"Name='Spooler'\"",
    "    $problems = @()",
    "    if ($service.Status -ne 'Running') { $problems += 'Spooler kjører ikke' }",
    "    if ($serviceConfig.StartMode -eq 'Disabled') { $problems += 'Spooler er deaktivert' }"
  ];
  if (clearStale) {
    detectionLines.push(
      `    $cutoff = (Get-Date).AddMinutes(-${staleMinutes})`,
      "    $spoolPath = Join-Path $env:SystemRoot 'System32\\spool\\PRINTERS'",
      '    $staleFiles = @(Get-ChildItem -Path $spoolPath -File -Force -ErrorAction SilentlyContinue | Where-Object { $_.LastWriteTime -lt $cutoff })',
      "    if ($staleFiles.Count -gt 0) { $problems += \"$($staleFiles.Count) gamle køfiler\" }"
    );
  }
  detectionLines.push(
    '',
    '    if ($problems.Count -eq 0) {',
    '        Write-Output "OK: Print Spooler og utskriftskøen ser friske ut."',
    '        exit 0',
    '    }',
    '    Write-Output ("AVVIK: {0}" -f ($problems -join "; "))',
    '    exit 1',
    '}',
    'catch {',
    '    Write-Output ("AVVIK: Kunne ikke kontrollere Print Spooler: {0}" -f $_.Exception.Message)',
    '    exit 1',
    '}'
  );

  const remediationLines = [
    scriptHeader('remediation', recipe, meta, clearStale
      ? 'Aktiverer Print Spooler og fjerner kun utskriftskøfiler som er eldre enn valgt grense.'
      : 'Aktiverer og starter Print Spooler uten å slette utskriftsjobber.'),
    '',
    'try {',
    "    Set-Service -Name 'Spooler' -StartupType Automatic"
  ];
  if (clearStale) {
    remediationLines.push(
      `    $cutoff = (Get-Date).AddMinutes(-${staleMinutes})`,
      "    $spoolPath = Join-Path $env:SystemRoot 'System32\\spool\\PRINTERS'",
      "    Stop-Service -Name 'Spooler' -Force -ErrorAction SilentlyContinue",
      '    $staleFiles = @(Get-ChildItem -Path $spoolPath -File -Force -ErrorAction SilentlyContinue | Where-Object { $_.LastWriteTime -lt $cutoff })',
      '    foreach ($file in $staleFiles) {',
      '        Remove-Item -LiteralPath $file.FullName -Force -ErrorAction SilentlyContinue',
      '    }'
    );
  }
  remediationLines.push(
    "    Start-Service -Name 'Spooler'",
    '    Write-Output "RETTET: Print Spooler kjører. Kontroller eventuelle brukerprintere og drivere separat."',
    '    exit 0',
    '}',
    'catch {',
    '    Write-Output ("FEIL: Print Spooler kunne ikke rettes: {0}" -f $_.Exception.Message)',
    '    exit 1',
    '}'
  );

  return { detection: detectionLines.join('\n'), remediation: remediationLines.join('\n') };
}

function teamsGenerator(params, meta, recipe) {
  const cacheLimitMB = clampNumber(params.cacheLimitMB, 50, 20000, 750);
  const closeTeams = Boolean(params.closeTeams);
  const detection = [
    scriptHeader('detection', recipe, meta, 'Måler kjente cacheområder for klassisk og ny Microsoft Teams i den påloggede brukerens profil.'),
    '',
    '$cachePaths = @(',
    "    (Join-Path $env:APPDATA 'Microsoft\\Teams'),",
    "    (Join-Path $env:LOCALAPPDATA 'Packages\\MSTeams_8wekyb3d8bbwe\\LocalCache\\Microsoft\\MSTeams')",
    ') | Where-Object { Test-Path $_ }',
    '',
    '$totalBytes = 0',
    'foreach ($path in $cachePaths) {',
    '    $measurement = Get-ChildItem -LiteralPath $path -File -Recurse -Force -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum',
    '    if ($measurement.Sum) { $totalBytes += [int64]$measurement.Sum }',
    '}',
    '$cacheMB = [math]::Round($totalBytes / 1MB, 1)',
    '',
    `if ($cacheMB -le ${cacheLimitMB}) {`,
    '    Write-Output ("OK: Teams-cache er {0} MB." -f $cacheMB)',
    '    exit 0',
    '}',
    '',
    `Write-Output ("AVVIK: Teams-cache er {0} MB og grensen er ${cacheLimitMB} MB." -f $cacheMB)`,
    'exit 1'
  ].join('\n');

  const remediationLines = [
    scriptHeader('remediation', recipe, meta, 'Tømmer utvalgte cacheområder for klassisk og ny Teams. Brukerkontekst anbefales.'),
    '',
    'try {'
  ];
  if (closeTeams) {
    remediationLines.push(
      "    Get-Process -Name 'Teams', 'ms-teams' -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue",
      '    Start-Sleep -Seconds 2'
    );
  }
  remediationLines.push(
    "    $classicRoot = Join-Path $env:APPDATA 'Microsoft\\Teams'",
    "    $newRoot = Join-Path $env:LOCALAPPDATA 'Packages\\MSTeams_8wekyb3d8bbwe\\LocalCache\\Microsoft\\MSTeams'",
    '    $targets = @(',
    "        (Join-Path $classicRoot 'Cache'),",
    "        (Join-Path $classicRoot 'Code Cache'),",
    "        (Join-Path $classicRoot 'GPUCache'),",
    "        (Join-Path $classicRoot 'IndexedDB'),",
    "        (Join-Path $classicRoot 'Local Storage'),",
    "        (Join-Path $classicRoot 'tmp'),",
    "        (Join-Path $newRoot 'EBWebView\\Default\\Cache'),",
    "        (Join-Path $newRoot 'EBWebView\\Default\\Code Cache'),",
    "        (Join-Path $newRoot 'EBWebView\\Default\\GPUCache')",
    '    )',
    '',
    '    foreach ($target in $targets) {',
    '        if (Test-Path $target) {',
    '            Get-ChildItem -LiteralPath $target -Force -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue',
    '        }',
    '    }',
    '',
    '    Write-Output "RETTET: Utvalgte Teams-cacheområder er tømt. Brukeren må eventuelt starte Teams på nytt."',
    '    exit 0',
    '}',
    'catch {',
    '    Write-Output ("FEIL: Teams-cache kunne ikke tømmes: {0}" -f $_.Exception.Message)',
    '    exit 1',
    '}'
  );

  return { detection, remediation: remediationLines.join('\n') };
}

function defenderGenerator(params, meta, recipe) {
  const maxSignatureAge = clampNumber(params.maxSignatureAge, 1, 30, 3);
  const updateSignatures = Boolean(params.updateSignatures);
  const enableRealtime = Boolean(params.enableRealtime);
  const detection = [
    scriptHeader('detection', recipe, meta, 'Kontrollerer Microsoft Defender Antivirus, sanntidsbeskyttelse og alderen på antivirus-signaturene.'),
    '',
    'try {',
    '    $status = Get-MpComputerStatus',
    '    $problems = @()',
    '',
    "    if (-not $status.AMServiceEnabled) { $problems += 'Defender-tjenesten er ikke aktiv' }",
    "    if (-not $status.AntivirusEnabled) { $problems += 'antivirus er ikke aktivert' }",
    "    if (-not $status.RealTimeProtectionEnabled) { $problems += 'sanntidsbeskyttelse er av' }",
    `    if ($status.AntivirusSignatureAge -gt ${maxSignatureAge}) { $problems += \"signaturene er $($status.AntivirusSignatureAge) dager gamle\" }`,
    '',
    '    if ($problems.Count -eq 0) {',
    '        Write-Output ("OK: Defender er aktiv og signaturene er {0} dager gamle." -f $status.AntivirusSignatureAge)',
    '        exit 0',
    '    }',
    '',
    '    Write-Output ("AVVIK: {0}" -f ($problems -join "; "))',
    '    exit 1',
    '}',
    'catch {',
    '    Write-Output ("AVVIK: Klarte ikke å lese Defender-status: {0}" -f $_.Exception.Message)',
    '    exit 1',
    '}'
  ].join('\n');

  const remediationLines = [
    scriptHeader('remediation', recipe, meta, 'Forsøker å aktivere sanntidsbeskyttelse og oppdatere Microsoft Defender-signaturene.'),
    '',
    'try {'
  ];
  if (enableRealtime) {
    remediationLines.push("    Set-MpPreference -DisableRealtimeMonitoring $false");
  }
  if (updateSignatures) {
    remediationLines.push('    Update-MpSignature');
  }
  remediationLines.push(
    '    Start-Sleep -Seconds 3',
    '    $status = Get-MpComputerStatus',
    `    if ($status.AMServiceEnabled -and $status.AntivirusEnabled -and $status.RealTimeProtectionEnabled -and $status.AntivirusSignatureAge -le ${maxSignatureAge}) {`,
    '        Write-Output "RETTET: Defender er aktiv og signaturene er innenfor ønsket alder."',
    '        exit 0',
    '    }',
    '',
    '    Write-Output ("FEIL: Defender er fortsatt ikke i ønsket tilstand. SignatureAge={0}; Realtime={1}." -f $status.AntivirusSignatureAge, $status.RealTimeProtectionEnabled)',
    '    exit 1',
    '}',
    'catch {',
    '    Write-Output ("FEIL: Defender kunne ikke rettes. Tamper Protection eller tredjeparts antivirus kan blokkere endringen: {0}" -f $_.Exception.Message)',
    '    exit 1',
    '}'
  );

  return { detection, remediation: remediationLines.join('\n') };
}

function diskGenerator(params, meta, recipe) {
  const drive = /^[A-Za-z]:$/.test(params.drive || '') ? params.drive.toUpperCase() : 'C:';
  const minFreeGB = clampNumber(params.minFreeGB, 1, 1000, 15);
  const minFreePercent = clampNumber(params.minFreePercent, 1, 99, 10);
  const tempAgeDays = clampNumber(params.tempAgeDays, 1, 365, 14);
  const clearDeliveryOptimization = Boolean(params.clearDeliveryOptimization);
  const detection = [
    scriptHeader('detection', recipe, meta, 'Kontrollerer ledig diskplass mot både en minimumsgrense i GB og prosent.'),
    '',
    'try {',
    `    $disk = Get-CimInstance -ClassName Win32_LogicalDisk -Filter \"DeviceID='${drive}'\"`,
    '    if (-not $disk) { throw "Fant ikke valgt disk." }',
    '',
    '    $freeGB = [math]::Round($disk.FreeSpace / 1GB, 1)',
    '    $freePercent = [math]::Round(($disk.FreeSpace / $disk.Size) * 100, 1)',
    '',
    `    if ($freeGB -ge ${minFreeGB} -and $freePercent -ge ${minFreePercent}) {`,
    '        Write-Output ("OK: Ledig plass er {0} GB ({1} %)." -f $freeGB, $freePercent)',
    '        exit 0',
    '    }',
    '',
    `    Write-Output ("AVVIK: Ledig plass er {0} GB ({1} %). Krav: minst ${minFreeGB} GB og ${minFreePercent} %." -f $freeGB, $freePercent)`,
    '    exit 1',
    '}',
    'catch {',
    '    Write-Output ("AVVIK: Diskplass kunne ikke kontrolleres: {0}" -f $_.Exception.Message)',
    '    exit 1',
    '}'
  ].join('\n');

  const remediationLines = [
    scriptHeader('remediation', recipe, meta, 'Fjerner gamle filer fra Windows- og prosessens tempområder, og kan tømme Delivery Optimization-cache.'),
    '',
    'try {',
    `    $cutoff = (Get-Date).AddDays(-${tempAgeDays})`,
    '    $cleanupPaths = @(',
    '        $env:TEMP,',
    "        (Join-Path $env:SystemRoot 'Temp')",
    '    ) | Select-Object -Unique',
    '',
    '    foreach ($path in $cleanupPaths) {',
    '        if (-not $path -or -not (Test-Path $path)) { continue }',
    '        Get-ChildItem -LiteralPath $path -File -Recurse -Force -ErrorAction SilentlyContinue |',
    '            Where-Object { $_.LastWriteTime -lt $cutoff } |',
    '            Remove-Item -Force -ErrorAction SilentlyContinue',
    '',
    '        Get-ChildItem -LiteralPath $path -Directory -Recurse -Force -ErrorAction SilentlyContinue |',
    '            Sort-Object -Property FullName -Descending |',
    '            Where-Object { -not (Get-ChildItem -LiteralPath $_.FullName -Force -ErrorAction SilentlyContinue) } |',
    '            Remove-Item -Force -ErrorAction SilentlyContinue',
    '    }'
  ];
  if (clearDeliveryOptimization) {
    remediationLines.push(
      '',
      '    if (Get-Command Delete-DeliveryOptimizationCache -ErrorAction SilentlyContinue) {',
      '        Delete-DeliveryOptimizationCache -Force -ErrorAction SilentlyContinue',
      '    }'
    );
  }
  remediationLines.push(
    '',
    `    $disk = Get-CimInstance -ClassName Win32_LogicalDisk -Filter \"DeviceID='${drive}'\"`,
    '    $freeGB = [math]::Round($disk.FreeSpace / 1GB, 1)',
    '    $freePercent = [math]::Round(($disk.FreeSpace / $disk.Size) * 100, 1)',
    `    if ($freeGB -ge ${minFreeGB} -and $freePercent -ge ${minFreePercent}) {`,
    '        Write-Output ("RETTET: Ledig plass er nå {0} GB ({1} %)." -f $freeGB, $freePercent)',
    '        exit 0',
    '    }',
    '',
    '    Write-Output ("MANUELL HANDLING: Opprydding fullført, men ledig plass er fortsatt {0} GB ({1} %)." -f $freeGB, $freePercent)',
    '    exit 1',
    '}',
    'catch {',
    '    Write-Output ("FEIL: Diskopprydding mislyktes: {0}" -f $_.Exception.Message)',
    '    exit 1',
    '}'
  );

  return { detection, remediation: remediationLines.join('\n') };
}

function serviceGenerator(params, meta, recipe) {
  const serviceName = params.serviceName || 'W32Time';
  const startupType = ['Automatic', 'Manual', 'Disabled'].includes(params.startupType) ? params.startupType : 'Automatic';
  const desiredStatus = startupType === 'Disabled' ? 'Stopped' : (params.expectedStatus === 'Stopped' ? 'Stopped' : 'Running');
  const cimStartMode = startupType === 'Automatic' ? 'Auto' : startupType;
  const detection = [
    scriptHeader('detection', recipe, meta, 'Kontrollerer at en valgt Windows-tjeneste finnes, har ønsket oppstartstype og ønsket status.'),
    '',
    `try {`,
    `    $serviceName = ${psString(serviceName)}`,
    '    $service = Get-Service -Name $serviceName -ErrorAction Stop',
    '    $serviceConfig = Get-CimInstance -ClassName Win32_Service -Filter "Name=\'$serviceName\'"',
    '    $problems = @()',
    '',
    `    if ($service.Status -ne '${desiredStatus}') { $problems += \"status er $($service.Status), ønsket ${desiredStatus}\" }`,
    `    if ($serviceConfig.StartMode -ne '${cimStartMode}') { $problems += \"oppstartstype er $($serviceConfig.StartMode), ønsket ${cimStartMode}\" }`,
    '',
    '    if ($problems.Count -eq 0) {',
    '        Write-Output ("OK: Tjenesten {0} er i ønsket tilstand." -f $serviceName)',
    '        exit 0',
    '    }',
    '    Write-Output ("AVVIK: {0}: {1}" -f $serviceName, ($problems -join "; "))',
    '    exit 1',
    '}',
    'catch {',
    '    Write-Output ("AVVIK: Tjenesten kunne ikke kontrolleres: {0}" -f $_.Exception.Message)',
    '    exit 1',
    '}'
  ].join('\n');

  const remediation = [
    scriptHeader('remediation', recipe, meta, 'Setter ønsket oppstartstype og starter eller stopper en valgt Windows-tjeneste.'),
    '',
    'try {',
    `    $serviceName = ${psString(serviceName)}`,
    '    $null = Get-Service -Name $serviceName -ErrorAction Stop',
    `    Set-Service -Name $serviceName -StartupType ${startupType}`,
    desiredStatus === 'Running'
      ? '    Start-Service -Name $serviceName'
      : '    Stop-Service -Name $serviceName -Force -ErrorAction SilentlyContinue',
    `    Write-Output ("RETTET: {0} har oppstartstype ${startupType} og ønsket status ${desiredStatus}." -f $serviceName)`,
    '    exit 0',
    '}',
    'catch {',
    '    Write-Output ("FEIL: Tjenesten kunne ikke rettes: {0}" -f $_.Exception.Message)',
    '    exit 1',
    '}'
  ].join('\n');

  return { detection, remediation };
}

function registryExpected(params) {
  const type = ['String', 'ExpandString', 'DWord', 'QWord'].includes(params.valueType) ? params.valueType : 'DWord';
  const raw = singleLine(params.desiredValue || '');
  if (type === 'DWord') {
    const value = /^\d+$/.test(raw) ? raw : '0';
    return { type, expression: `[uint32]${psString(value)}`, display: value };
  }
  if (type === 'QWord') {
    const value = /^\d+$/.test(raw) ? raw : '0';
    return { type, expression: `[uint64]${psString(value)}`, display: value };
  }
  return { type, expression: psString(raw), display: raw };
}

function registryGenerator(params, meta, recipe) {
  const hive = params.hive === 'HKCU' ? 'HKCU' : 'HKLM';
  const cleanPath = String(params.registryPath || 'SOFTWARE\\Contoso').replace(/^(HKLM|HKCU):?\\?/i, '').replace(/^\\+/, '');
  const registryPath = `${hive}:\\${cleanPath}`;
  const valueName = params.valueName || 'Enabled';
  const expected = registryExpected(params);
  const detection = [
    scriptHeader('detection', recipe, meta, 'Kontrollerer at en registerverdi finnes og samsvarer med ønsket verdi.'),
    '',
    `try {`,
    `    $registryPath = ${psString(registryPath)}`,
    `    $valueName = ${psString(valueName)}`,
    `    $expectedValue = ${expected.expression}`,
    '',
    '    if (-not (Test-Path $registryPath)) {',
    '        Write-Output ("AVVIK: Registernøkkelen finnes ikke: {0}" -f $registryPath)',
    '        exit 1',
    '    }',
    '',
    '    $actualValue = Get-ItemPropertyValue -Path $registryPath -Name $valueName -ErrorAction Stop',
    '    if ([string]$actualValue -eq [string]$expectedValue) {',
    '        Write-Output ("OK: {0}\\{1} har ønsket verdi {2}." -f $registryPath, $valueName, $actualValue)',
    '        exit 0',
    '    }',
    '',
    '    Write-Output ("AVVIK: {0}\\{1} er {2}; forventet {3}." -f $registryPath, $valueName, $actualValue, $expectedValue)',
    '    exit 1',
    '}',
    'catch {',
    '    Write-Output ("AVVIK: Registerverdien mangler eller kunne ikke leses: {0}" -f $_.Exception.Message)',
    '    exit 1',
    '}'
  ].join('\n');

  const remediation = [
    scriptHeader('remediation', recipe, meta, 'Oppretter registernøkkelen ved behov og setter ønsket verdi og datatype.'),
    '',
    'try {',
    `    $registryPath = ${psString(registryPath)}`,
    `    $valueName = ${psString(valueName)}`,
    `    $desiredValue = ${expected.expression}`,
    '',
    '    if (-not (Test-Path $registryPath)) {',
    '        New-Item -Path $registryPath -Force | Out-Null',
    '    }',
    '',
    `    New-ItemProperty -Path $registryPath -Name $valueName -PropertyType ${expected.type} -Value $desiredValue -Force | Out-Null`,
    '    Write-Output ("RETTET: {0}\\{1} er satt til {2}." -f $registryPath, $valueName, $desiredValue)',
    '    exit 0',
    '}',
    'catch {',
    '    Write-Output ("FEIL: Registerverdien kunne ikke settes: {0}" -f $_.Exception.Message)',
    '    exit 1',
    '}'
  ].join('\n');

  return { detection, remediation };
}

function customGenerator(params, meta, recipe) {
  const purpose = params.purpose || 'Beskriv ønsket tilstand og erstatt TODO-delene før produksjon.';
  const detection = [
    scriptHeader('detection', recipe, meta, purpose),
    '',
    '# TODO: Erstatt denne eksempelverdien med faktisk deteksjonslogikk.',
    '$issueDetected = $false',
    '',
    'if ($issueDetected) {',
    '    Write-Output "AVVIK: Beskriv hva som ble funnet."',
    '    exit 1',
    '}',
    '',
    'Write-Output "OK: Beskriv hvorfor enheten er i ønsket tilstand."',
    'exit 0'
  ].join('\n');

  const remediation = [
    scriptHeader('remediation', recipe, meta, purpose),
    '',
    'try {',
    '    # TODO: Legg inn sikker og idempotent remediation-logikk.',
    '    # TODO: Bekreft ønsket tilstand etter endringen.',
    '',
    '    Write-Output "RETTET: Beskriv hva som ble endret."',
    '    exit 0',
    '}',
    'catch {',
    '    Write-Output ("FEIL: Remediation mislyktes: {0}" -f $_.Exception.Message)',
    '    exit 1',
    '}'
  ].join('\n');

  return { detection, remediation };
}

const recipes = [
  {
    id: 'bitlocker',
    name: 'BitLocker',
    icon: '🔐',
    category: 'Sikkerhet',
    risk: 'medium',
    riskLabel: 'Middels risiko',
    summary: 'Kontroller kryptering og gjenoppta eller aktiver beskyttelse.',
    description: 'Sjekker OS-volumets krypterings- og beskyttelsesstatus. Standardvalget gjenopptar kun eksisterende BitLocker-beskyttelse.',
    defaultPackage: 'Kontroller BitLocker-beskyttelse',
    defaults: { bitlockerAction: 'resume', encryptionMethod: 'XtsAes256', usedSpaceOnly: true, backupAad: true },
    fields: [
      { id: 'bitlockerAction', label: 'Remediation-handling', type: 'select', options: [
        ['resume', 'Kun gjenoppta beskyttelse – anbefalt'],
        ['enable', 'Aktiver BitLocker hvis ukryptert – avansert']
      ], help: 'Velg sikker standard eller eksplisitt aktivering av kryptering.' },
      { id: 'encryptionMethod', label: 'Krypteringsmetode', type: 'select', options: [['XtsAes256', 'XTS-AES 256'], ['XtsAes128', 'XTS-AES 128']], help: 'Brukes bare dersom aktivering er valgt.' },
      { id: 'usedSpaceOnly', label: 'Krypter bare brukt plass', type: 'checkbox', help: 'Raskere på nye enheter, men vurder organisasjonens BitLocker-policy.' },
      { id: 'backupAad', label: 'Forsøk nøkkelbackup til Entra ID', type: 'checkbox', help: 'Krever at cmdleten og tenant-konfigurasjonen støtter escrow.' }
    ],
    testFields: [
      { id: 'encrypted', label: 'Volumet er fullstendig kryptert', type: 'checkbox', default: true },
      { id: 'protected', label: 'ProtectionStatus er On', type: 'checkbox', default: false }
    ],
    defaultsIntune: { runAsUser: false, run64Bit: true, signatureCheck: false, schedule: 'daily' },
    generate: bitLockerGenerator,
    simulate: (params, test) => {
      if (test.encrypted && test.protected) return { exitCode: 0, message: 'OK: BitLocker er fullstendig kryptert og beskyttelsen er aktiv.', details: ['VolumeStatus = FullyEncrypted', 'ProtectionStatus = On'] };
      return { exitCode: 1, message: `AVVIK: VolumeStatus=${test.encrypted ? 'FullyEncrypted' : 'FullyDecrypted'}; ProtectionStatus=${test.protected ? 'On' : 'Off'}.`, details: ['Intune ville startet Remediation.ps1.'] };
    }
  },
  {
    id: 'onedrive',
    name: 'OneDrive',
    icon: '☁️',
    category: 'Bruker',
    risk: 'low',
    riskLabel: 'Lav risiko',
    summary: 'Kontroller at OneDrive er installert og kjører for brukeren.',
    description: 'Sjekker om OneDrive.exe finnes og om prosessen kjører. Remediation starter klienten i brukerens kontekst.',
    defaultPackage: 'Start OneDrive-klienten',
    defaults: { startupArgs: '/background' },
    fields: [
      { id: 'startupArgs', label: 'Startargumenter', type: 'text', default: '/background', help: 'Standard er /background. Ikke legg inn hemmeligheter eller brukerspesifikke data.' }
    ],
    testFields: [
      { id: 'installed', label: 'OneDrive.exe er installert', type: 'checkbox', default: true },
      { id: 'running', label: 'OneDrive-prosessen kjører', type: 'checkbox', default: false }
    ],
    defaultsIntune: { runAsUser: true, run64Bit: false, signatureCheck: false, schedule: 'daily' },
    generate: oneDriveGenerator,
    simulate: (params, test) => {
      if (test.installed && test.running) return { exitCode: 0, message: 'OK: OneDrive-klienten kjører.', details: ['OneDrive.exe ble funnet.', 'Prosessen OneDrive kjører.'] };
      if (!test.installed) return { exitCode: 1, message: 'AVVIK: OneDrive.exe ble ikke funnet.', details: ['Distribuer OneDrive før remediation forsøker å starte klienten.'] };
      return { exitCode: 1, message: 'AVVIK: OneDrive er installert, men prosessen kjører ikke.', details: ['Intune ville startet Remediation.ps1.'] };
    }
  },
  {
    id: 'windows-update',
    name: 'Windows Update',
    icon: '↻',
    category: 'Vedlikehold',
    risk: 'low',
    riskLabel: 'Lav risiko',
    summary: 'Finn deaktiverte oppdateringstjenester og start oppdateringssøk.',
    description: 'Kontrollerer wuauserv, BITS og UsoSvc. Remediation aktiverer deaktiverte tjenester og kan starte et nytt oppdateringssøk.',
    defaultPackage: 'Reparer Windows Update-tjenester',
    defaults: { triggerScan: true },
    fields: [
      { id: 'triggerScan', label: 'Start oppdateringssøk etter retting', type: 'checkbox', help: 'Starter UsoClient StartScan når verktøyet finnes.' }
    ],
    testFields: [
      { id: 'disabledServices', label: 'Antall manglende eller deaktiverte tjenester', type: 'number', default: 1, min: 0, max: 3 }
    ],
    defaultsIntune: { runAsUser: false, run64Bit: true, signatureCheck: false, schedule: 'daily' },
    generate: windowsUpdateGenerator,
    simulate: (params, test) => Number(test.disabledServices) === 0
      ? { exitCode: 0, message: 'OK: Windows Update-tjenestene er tilgjengelige og ikke deaktivert.', details: ['wuauserv, BITS og UsoSvc er kontrollert.'] }
      : { exitCode: 1, message: `AVVIK: ${Number(test.disabledServices)} tjeneste(r) mangler eller er deaktivert.`, details: ['Intune ville startet Remediation.ps1.'] }
  },
  {
    id: 'printers',
    name: 'Printere',
    icon: '🖨️',
    category: 'Tjenester',
    risk: 'medium',
    riskLabel: 'Middels risiko',
    summary: 'Kontroller Print Spooler og valgfritt rydd gamle køfiler.',
    description: 'Sjekker Print Spooler og kan fjerne bare køfiler som er eldre enn valgt tidsgrense. Test mot faktiske skriverløsninger.',
    defaultPackage: 'Reparer Print Spooler',
    defaults: { clearStaleJobs: false, staleMinutes: 60 },
    fields: [
      { id: 'clearStaleJobs', label: 'Fjern gamle filer fra utskriftskøen', type: 'checkbox', help: 'Kan fjerne fastlåste utskriftsjobber. Standard er av.' },
      { id: 'staleMinutes', label: 'Regn køfiler som gamle etter', suffix: 'minutter', type: 'number', default: 60, min: 5, max: 1440, help: 'Kun filer eldre enn grensen slettes når opprydding er aktivert.' }
    ],
    testFields: [
      { id: 'spoolerRunning', label: 'Print Spooler kjører', type: 'checkbox', default: false },
      { id: 'staleJobs', label: 'Antall gamle køfiler', type: 'number', default: 2, min: 0, max: 100 }
    ],
    defaultsIntune: { runAsUser: false, run64Bit: true, signatureCheck: false, schedule: 'daily' },
    generate: printerGenerator,
    simulate: (params, test) => {
      const hasStale = Boolean(params.clearStaleJobs) && Number(test.staleJobs) > 0;
      if (test.spoolerRunning && !hasStale) return { exitCode: 0, message: 'OK: Print Spooler og utskriftskøen ser friske ut.', details: ['Spooler = Running'] };
      const issues = [];
      if (!test.spoolerRunning) issues.push('Spooler kjører ikke');
      if (hasStale) issues.push(`${Number(test.staleJobs)} gamle køfiler`);
      return { exitCode: 1, message: `AVVIK: ${issues.join('; ')}.`, details: ['Intune ville startet Remediation.ps1.'] };
    }
  },
  {
    id: 'teams-cache',
    name: 'Teams-cache',
    icon: '💬',
    category: 'Bruker',
    risk: 'medium',
    riskLabel: 'Middels risiko',
    summary: 'Mål og tøm utvalgte cacheområder for klassisk og ny Teams.',
    description: 'Måler cache i brukerprofilen og rydder utvalgte områder. Remediation kan stoppe Teams-prosessen før opprydding.',
    defaultPackage: 'Rydd Microsoft Teams-cache',
    defaults: { cacheLimitMB: 750, closeTeams: true },
    fields: [
      { id: 'cacheLimitMB', label: 'Maksimal cache', suffix: 'MB', type: 'number', default: 750, min: 50, max: 20000, help: 'Detection returnerer exit 1 når samlet cache er større enn grensen.' },
      { id: 'closeTeams', label: 'Stopp Teams før opprydding', type: 'checkbox', help: 'Kan avbryte en aktiv Teams-økt. Informer brukerne ved behov.' }
    ],
    testFields: [
      { id: 'cacheMB', label: 'Simulert Teams-cache', suffix: 'MB', type: 'number', default: 1250, min: 0, max: 50000 }
    ],
    defaultsIntune: { runAsUser: true, run64Bit: false, signatureCheck: false, schedule: 'weekly' },
    generate: teamsGenerator,
    simulate: (params, test) => Number(test.cacheMB) <= Number(params.cacheLimitMB)
      ? { exitCode: 0, message: `OK: Teams-cache er ${Number(test.cacheMB)} MB.`, details: [`Grense = ${Number(params.cacheLimitMB)} MB`] }
      : { exitCode: 1, message: `AVVIK: Teams-cache er ${Number(test.cacheMB)} MB og grensen er ${Number(params.cacheLimitMB)} MB.`, details: ['Intune ville startet Remediation.ps1.'] }
  },
  {
    id: 'defender',
    name: 'Microsoft Defender',
    icon: '🛡️',
    category: 'Sikkerhet',
    risk: 'low',
    riskLabel: 'Lav risiko',
    summary: 'Kontroller antivirus, sanntidsbeskyttelse og signaturalder.',
    description: 'Sjekker Defender Antivirus og forsøker å aktivere sanntidsbeskyttelse og oppdatere signaturer. Tamper Protection kan blokkere endringer.',
    defaultPackage: 'Kontroller Microsoft Defender',
    defaults: { maxSignatureAge: 3, updateSignatures: true, enableRealtime: true },
    fields: [
      { id: 'maxSignatureAge', label: 'Maksimal signaturalder', suffix: 'dager', type: 'number', default: 3, min: 1, max: 30, help: 'Eldre signaturer utløser remediation.' },
      { id: 'updateSignatures', label: 'Oppdater Defender-signaturer', type: 'checkbox', help: 'Kjører Update-MpSignature.' },
      { id: 'enableRealtime', label: 'Aktiver sanntidsbeskyttelse', type: 'checkbox', help: 'Kjører Set-MpPreference. Tamper Protection kan overstyre dette.' }
    ],
    testFields: [
      { id: 'antivirusEnabled', label: 'Antivirus er aktivert', type: 'checkbox', default: true },
      { id: 'realtimeEnabled', label: 'Sanntidsbeskyttelse er aktiv', type: 'checkbox', default: false },
      { id: 'signatureAge', label: 'Simulert signaturalder', suffix: 'dager', type: 'number', default: 6, min: 0, max: 365 }
    ],
    defaultsIntune: { runAsUser: false, run64Bit: true, signatureCheck: false, schedule: 'daily' },
    generate: defenderGenerator,
    simulate: (params, test) => {
      const problems = [];
      if (!test.antivirusEnabled) problems.push('antivirus er ikke aktivert');
      if (!test.realtimeEnabled) problems.push('sanntidsbeskyttelse er av');
      if (Number(test.signatureAge) > Number(params.maxSignatureAge)) problems.push(`signaturene er ${Number(test.signatureAge)} dager gamle`);
      if (!problems.length) return { exitCode: 0, message: `OK: Defender er aktiv og signaturene er ${Number(test.signatureAge)} dager gamle.`, details: ['Alle valgte kontroller er bestått.'] };
      return { exitCode: 1, message: `AVVIK: ${problems.join('; ')}.`, details: ['Intune ville startet Remediation.ps1.'] };
    }
  },
  {
    id: 'disk-space',
    name: 'Diskplass',
    icon: '◫',
    category: 'Vedlikehold',
    risk: 'low',
    riskLabel: 'Lav risiko',
    summary: 'Kontroller ledig plass og rydd gamle tempfiler.',
    description: 'Måler ledig plass i GB og prosent. Remediation rydder gamle filer i tempområder og kan tømme Delivery Optimization-cache.',
    defaultPackage: 'Rydd diskplass',
    defaults: { drive: 'C:', minFreeGB: 15, minFreePercent: 10, tempAgeDays: 14, clearDeliveryOptimization: true },
    fields: [
      { id: 'drive', label: 'Disk', type: 'text', default: 'C:', help: 'Bruk formatet C: eller D:.' },
      { id: 'minFreeGB', label: 'Minimum ledig plass', suffix: 'GB', type: 'number', default: 15, min: 1, max: 1000 },
      { id: 'minFreePercent', label: 'Minimum ledig plass', suffix: '%', type: 'number', default: 10, min: 1, max: 99 },
      { id: 'tempAgeDays', label: 'Slett tempfiler eldre enn', suffix: 'dager', type: 'number', default: 14, min: 1, max: 365 },
      { id: 'clearDeliveryOptimization', label: 'Tøm Delivery Optimization-cache', type: 'checkbox', help: 'Kjøres bare dersom cmdleten finnes på enheten.' }
    ],
    testFields: [
      { id: 'freeGB', label: 'Simulert ledig plass', suffix: 'GB', type: 'number', default: 7, min: 0, max: 2000 },
      { id: 'freePercent', label: 'Simulert ledig plass', suffix: '%', type: 'number', default: 6, min: 0, max: 100 }
    ],
    defaultsIntune: { runAsUser: false, run64Bit: true, signatureCheck: false, schedule: 'daily' },
    generate: diskGenerator,
    simulate: (params, test) => {
      const compliant = Number(test.freeGB) >= Number(params.minFreeGB) && Number(test.freePercent) >= Number(params.minFreePercent);
      return compliant
        ? { exitCode: 0, message: `OK: Ledig plass er ${Number(test.freeGB)} GB (${Number(test.freePercent)} %).`, details: ['Begge terskler er bestått.'] }
        : { exitCode: 1, message: `AVVIK: Ledig plass er ${Number(test.freeGB)} GB (${Number(test.freePercent)} %).`, details: [`Krav: minst ${Number(params.minFreeGB)} GB og ${Number(params.minFreePercent)} %.`, 'Intune ville startet Remediation.ps1.'] };
    }
  },
  {
    id: 'services',
    name: 'Windows-tjeneste',
    icon: '⚙️',
    category: 'Tjenester',
    risk: 'medium',
    riskLabel: 'Middels risiko',
    summary: 'Bygg en generell kontroll for status og oppstartstype.',
    description: 'Velg tjenestenavn, ønsket status og oppstartstype. Remediation endrer tjenesten til ønsket tilstand.',
    defaultPackage: 'Kontroller Windows-tjeneste',
    defaults: { serviceName: 'W32Time', expectedStatus: 'Running', startupType: 'Automatic' },
    fields: [
      { id: 'serviceName', label: 'Tjenestenavn', type: 'text', default: 'W32Time', help: 'Bruk service name, ikke display name. Eksempel: W32Time.' },
      { id: 'expectedStatus', label: 'Ønsket status', type: 'select', options: [['Running', 'Kjører'], ['Stopped', 'Stoppet']] },
      { id: 'startupType', label: 'Ønsket oppstartstype', type: 'select', options: [['Automatic', 'Automatic'], ['Manual', 'Manual'], ['Disabled', 'Disabled']] }
    ],
    testFields: [
      { id: 'exists', label: 'Tjenesten finnes', type: 'checkbox', default: true },
      { id: 'status', label: 'Simulert status', type: 'select', default: 'Stopped', options: [['Running', 'Running'], ['Stopped', 'Stopped']] },
      { id: 'startupType', label: 'Simulert oppstartstype', type: 'select', default: 'Manual', options: [['Automatic', 'Automatic'], ['Manual', 'Manual'], ['Disabled', 'Disabled']] }
    ],
    defaultsIntune: { runAsUser: false, run64Bit: true, signatureCheck: false, schedule: 'daily' },
    validate: (params) => /^[A-Za-z0-9_.-]+$/.test(params.serviceName || '') ? [] : ['Tjenestenavnet kan bare inneholde bokstaver, tall, punktum, bindestrek og understrek.'],
    generate: serviceGenerator,
    simulate: (params, test) => {
      if (!test.exists) return { exitCode: 1, message: 'AVVIK: Tjenesten ble ikke funnet.', details: ['Kontroller service name og Windows-versjon.'] };
      const desiredStatus = params.startupType === 'Disabled' ? 'Stopped' : params.expectedStatus;
      const problems = [];
      if (test.status !== desiredStatus) problems.push(`status er ${test.status}, ønsket ${desiredStatus}`);
      if (test.startupType !== params.startupType) problems.push(`oppstartstype er ${test.startupType}, ønsket ${params.startupType}`);
      if (!problems.length) return { exitCode: 0, message: `OK: ${params.serviceName} er i ønsket tilstand.`, details: [`Status = ${desiredStatus}`, `StartupType = ${params.startupType}`] };
      return { exitCode: 1, message: `AVVIK: ${params.serviceName}: ${problems.join('; ')}.`, details: ['Intune ville startet Remediation.ps1.'] };
    }
  },
  {
    id: 'registry',
    name: 'Registry-innstilling',
    icon: '▦',
    category: 'Konfigurasjon',
    risk: 'medium',
    riskLabel: 'Middels risiko',
    summary: 'Kontroller og sett en HKLM- eller HKCU-registerverdi.',
    description: 'Bygger en idempotent kontroll for String, ExpandString, DWord eller QWord. HKCU krever vanligvis pålogget brukerkontekst.',
    defaultPackage: 'Kontroller registerinnstilling',
    defaults: { hive: 'HKLM', registryPath: 'SOFTWARE\\Contoso\\Settings', valueName: 'Enabled', valueType: 'DWord', desiredValue: '1' },
    fields: [
      { id: 'hive', label: 'Registerhive', type: 'select', options: [['HKLM', 'HKEY_LOCAL_MACHINE'], ['HKCU', 'HKEY_CURRENT_USER']] },
      { id: 'registryPath', label: 'Nøkkelsti', type: 'text', default: 'SOFTWARE\\Contoso\\Settings', help: 'Skriv stien uten HKLM: eller HKCU:.' },
      { id: 'valueName', label: 'Verdinavn', type: 'text', default: 'Enabled' },
      { id: 'valueType', label: 'Datatype', type: 'select', options: [['DWord', 'DWORD (32-bit)'], ['QWord', 'QWORD (64-bit)'], ['String', 'String'], ['ExpandString', 'Expandable String']] },
      { id: 'desiredValue', label: 'Ønsket verdi', type: 'text', default: '1', help: 'DWORD/QWORD må være et heltall.' }
    ],
    testFields: [
      { id: 'exists', label: 'Registerverdien finnes', type: 'checkbox', default: false },
      { id: 'actualValue', label: 'Simulert faktisk verdi', type: 'text', default: '0' }
    ],
    defaultsIntune: { runAsUser: false, run64Bit: true, signatureCheck: false, schedule: 'daily' },
    validate: (params) => {
      const errors = [];
      if (!String(params.registryPath || '').trim()) errors.push('Nøkkelsti kan ikke være tom.');
      if (!String(params.valueName || '').trim()) errors.push('Verdinavn kan ikke være tomt.');
      if (['DWord', 'QWord'].includes(params.valueType)) {
        const raw = String(params.desiredValue || '').trim();
        if (!/^\d+$/.test(raw)) {
          errors.push('DWORD/QWORD må ha et positivt heltall eller 0.');
        } else {
          try {
            const value = BigInt(raw);
            const max = params.valueType === 'DWord' ? 4294967295n : 18446744073709551615n;
            if (value > max) errors.push(`${params.valueType} er høyere enn tillatt maksimum.`);
          } catch {
            errors.push('DWORD/QWORD-verdien kunne ikke tolkes.');
          }
        }
      }
      return errors;
    },
    generate: registryGenerator,
    simulate: (params, test) => {
      if (!test.exists) return { exitCode: 1, message: 'AVVIK: Registerverdien mangler.', details: ['Intune ville startet Remediation.ps1.'] };
      const expected = registryExpected(params).display;
      if (String(test.actualValue) === String(expected)) return { exitCode: 0, message: `OK: Registerverdien er ${expected}.`, details: ['Faktisk verdi samsvarer med ønsket verdi.'] };
      return { exitCode: 1, message: `AVVIK: Registerverdien er ${String(test.actualValue)}; forventet ${expected}.`, details: ['Intune ville startet Remediation.ps1.'] };
    }
  },
  {
    id: 'custom',
    name: 'Egendefinert',
    icon: '</>',
    category: 'Avansert',
    risk: 'high',
    riskLabel: 'Krever gjennomgang',
    summary: 'Start med et ryddig, redigerbart PowerShell-skjelett.',
    description: 'Gir et generelt scriptpar med riktig exit code-struktur. TODO-delene må erstattes og testes før opplasting.',
    defaultPackage: 'Egendefinert remediation',
    defaults: { purpose: 'Beskriv ønsket tilstand og hva scriptet skal rette.' },
    fields: [
      { id: 'purpose', label: 'Formål', type: 'textarea', default: 'Beskriv ønsket tilstand og hva scriptet skal rette.', help: 'Brukes i scriptkommentarene. Ikke inkluder sensitiv informasjon.' }
    ],
    testFields: [
      { id: 'issueDetected', label: 'Simuler at egendefinert logikk finner et avvik', type: 'checkbox', default: false }
    ],
    defaultsIntune: { runAsUser: false, run64Bit: true, signatureCheck: false, schedule: 'daily' },
    generate: customGenerator,
    simulate: (params, test) => test.issueDetected
      ? { exitCode: 1, message: 'AVVIK: Simulert egendefinert logikk fant et avvik.', details: ['Erstatt TODO-logikken før produksjon.'] }
      : { exitCode: 0, message: 'OK: Simulert egendefinert logikk fant ingen avvik.', details: ['Erstatt TODO-logikken før produksjon.'] }
  }
];

function defaultValues(recipe) {
  const values = { ...(recipe.defaults || {}) };
  for (const field of recipe.fields || []) {
    if (!(field.id in values) && field.default !== undefined) values[field.id] = field.default;
    if (!(field.id in values) && field.type === 'checkbox') values[field.id] = false;
    if (!(field.id in values) && field.type === 'select' && field.options?.length) values[field.id] = field.options[0][0];
  }
  return values;
}

function defaultTestValues(recipe) {
  const values = {};
  for (const field of recipe.testFields || []) {
    if (field.default !== undefined) values[field.id] = field.default;
    else if (field.type === 'checkbox') values[field.id] = false;
    else if (field.type === 'select' && field.options?.length) values[field.id] = field.options[0][0];
    else values[field.id] = '';
  }
  return values;
}

function renderQuickRecipeOptions() {
  $('quickRecipe').innerHTML = '';
  for (const recipe of recipes) {
    const option = document.createElement('option');
    option.value = recipe.id;
    option.textContent = `${recipe.name} – ${recipe.summary}`;
    $('quickRecipe').appendChild(option);
  }
  $('quickRecipe').value = state.selectedRecipeId;
}

function renderRecipeGrid(filter = '') {
  const query = filter.trim().toLowerCase();
  const matches = recipes.filter((recipe) => [recipe.name, recipe.category, recipe.summary, recipe.description].join(' ').toLowerCase().includes(query));
  const grid = $('recipeGrid');
  grid.innerHTML = '';

  if (!matches.length) {
    const empty = document.createElement('div');
    empty.className = 'empty-recipes';
    empty.textContent = 'Ingen oppskrifter samsvarer med søket.';
    grid.appendChild(empty);
    return;
  }

  for (const recipe of matches) {
    const button = document.createElement('button');
    button.type = 'button';
    button.className = `recipe-card${recipe.id === state.selectedRecipeId ? ' selected' : ''}`;
    button.dataset.recipe = recipe.id;
    button.setAttribute('aria-pressed', recipe.id === state.selectedRecipeId ? 'true' : 'false');

    const top = document.createElement('div');
    top.className = 'recipe-card-top';
    const icon = document.createElement('span');
    icon.className = 'recipe-icon';
    icon.textContent = recipe.icon;
    const category = document.createElement('span');
    category.className = 'category-badge';
    category.textContent = recipe.category;
    top.append(icon, category);

    const title = document.createElement('h3');
    title.textContent = recipe.name;
    const description = document.createElement('p');
    description.textContent = recipe.summary;

    const footer = document.createElement('div');
    footer.className = 'recipe-card-footer';
    const action = document.createElement('span');
    action.textContent = recipe.id === state.selectedRecipeId ? 'Valgt oppskrift' : 'Bruk oppskrift →';
    const risk = document.createElement('span');
    risk.className = `risk-dot ${recipe.risk}`;
    risk.textContent = recipe.riskLabel;
    footer.append(action, risk);

    button.append(top, title, description, footer);
    grid.appendChild(button);
  }
}

function createField(field, value, namespace = 'field') {
  if (field.type === 'checkbox') {
    const wrapper = document.createElement('label');
    wrapper.className = 'checkbox-field';
    const input = document.createElement('input');
    input.type = 'checkbox';
    input.id = `${namespace}-${field.id}`;
    input.name = field.id;
    input.checked = Boolean(value);
    const text = document.createElement('div');
    const strong = document.createElement('strong');
    strong.textContent = field.label;
    const help = document.createElement('span');
    help.textContent = field.help || '';
    text.append(strong, help);
    wrapper.append(input, text);
    return wrapper;
  }

  const wrapper = document.createElement('div');
  wrapper.className = 'form-field';
  const label = document.createElement('label');
  label.htmlFor = `${namespace}-${field.id}`;
  label.textContent = field.label;
  if (field.suffix) {
    const suffix = document.createElement('span');
    suffix.textContent = ` (${field.suffix})`;
    label.appendChild(suffix);
  }

  let input;
  if (field.type === 'select') {
    input = document.createElement('select');
    for (const [optionValue, optionLabel] of field.options || []) {
      const option = document.createElement('option');
      option.value = optionValue;
      option.textContent = optionLabel;
      input.appendChild(option);
    }
    input.value = value ?? '';
  } else if (field.type === 'textarea') {
    input = document.createElement('textarea');
    input.value = value ?? '';
  } else {
    input = document.createElement('input');
    input.type = field.type || 'text';
    input.value = value ?? '';
    if (field.min !== undefined) input.min = String(field.min);
    if (field.max !== undefined) input.max = String(field.max);
    if (field.step !== undefined) input.step = String(field.step);
    if (field.maxLength !== undefined) input.maxLength = Number(field.maxLength);
    if (input.type === 'text') input.spellcheck = false;
  }
  input.id = `${namespace}-${field.id}`;
  input.name = field.id;

  wrapper.append(label, input);
  if (field.help) {
    const help = document.createElement('div');
    help.className = 'field-help';
    help.textContent = field.help;
    wrapper.appendChild(help);
  }
  return wrapper;
}

function renderConfigForm() {
  const recipe = currentRecipe();
  const values = state.recipeValues[recipe.id] || defaultValues(recipe);
  state.recipeValues[recipe.id] = values;
  const form = $('configForm');
  form.innerHTML = '';

  const packageField = createField({ id: 'packageName', label: 'Pakkenavn', type: 'text', maxLength: 90, help: 'Brukes i kommentarene, ZIP-navnet og README-filen.' }, state.packageName, 'field');
  form.appendChild(packageField);
  for (const field of recipe.fields) form.appendChild(createField(field, values[field.id], 'field'));

  form.querySelectorAll('input,select,textarea').forEach((input) => {
    input.addEventListener('input', handleConfigInput);
    input.addEventListener('change', handleConfigInput);
  });
}

function readFormValues(form, fields, namespace) {
  const values = {};
  for (const field of fields) {
    const input = form.querySelector(`#${namespace}-${CSS.escape(field.id)}`);
    if (!input) continue;
    if (field.type === 'checkbox') values[field.id] = input.checked;
    else if (field.type === 'number') values[field.id] = Number(input.value);
    else values[field.id] = input.value;
  }
  return values;
}

function handleConfigInput(event) {
  const recipe = currentRecipe();
  if (event.target.name === 'packageName') {
    state.packageName = event.target.value;
    $('quickPackageName').value = state.packageName;
  } else {
    state.recipeValues[recipe.id] = readFormValues($('configForm'), recipe.fields, 'field');
  }
  state.configDirty = true;
  updateBuilderStatus();
  renderConfigWarnings();
  updatePackageSummary();
}

function renderTestForm() {
  const recipe = currentRecipe();
  const values = state.testValues[recipe.id] || defaultTestValues(recipe);
  state.testValues[recipe.id] = values;
  const form = $('testForm');
  form.innerHTML = '';
  for (const field of recipe.testFields) form.appendChild(createField(field, values[field.id], 'test'));
  form.querySelectorAll('input,select,textarea').forEach((input) => {
    input.addEventListener('input', () => {
      state.testValues[recipe.id] = readFormValues(form, recipe.testFields, 'test');
    });
    input.addEventListener('change', () => {
      state.testValues[recipe.id] = readFormValues(form, recipe.testFields, 'test');
    });
  });
  $('testRecipeName').textContent = recipe.name;
  resetTestConsole();
}

function applyRecipeDefaults(recipe) {
  $('runAsUser').value = recipe.defaultsIntune.runAsUser ? 'yes' : 'no';
  $('run64Bit').value = recipe.defaultsIntune.run64Bit ? 'yes' : 'no';
  $('signatureCheck').value = recipe.defaultsIntune.signatureCheck ? 'yes' : 'no';
  $('schedule').value = recipe.defaultsIntune.schedule;
}

function activateRecipe(recipeId, options = {}) {
  const recipe = recipes.find((item) => item.id === recipeId);
  if (!recipe) return;
  state.selectedRecipeId = recipe.id;
  if (options.reset || !state.recipeValues[recipe.id]) state.recipeValues[recipe.id] = defaultValues(recipe);
  if (options.reset || !state.testValues[recipe.id]) state.testValues[recipe.id] = defaultTestValues(recipe);
  state.packageName = options.packageName?.trim() || (options.keepPackageName ? state.packageName : recipe.defaultPackage);
  $('quickRecipe').value = recipe.id;
  $('quickPackageName').value = state.packageName;
  $('activeRecipeName').textContent = recipe.name;
  $('activeRecipeIcon').textContent = recipe.icon;
  $('activeRecipeDescription').textContent = recipe.description;
  $('activeRecipeRisk').textContent = recipe.riskLabel;
  $('activeRecipeRisk').className = `risk-badge risk-${recipe.risk}`;
  renderRecipeGrid($('recipeSearch').value);
  renderConfigForm();
  renderTestForm();
  applyRecipeDefaults(recipe);
  generateScripts(false);
  if (options.scroll) $('builder').scrollIntoView({ behavior: 'smooth', block: 'start' });
}

function validateParams(recipe, params) {
  const errors = [];
  if (!state.packageName.trim()) errors.push('Pakkenavn kan ikke være tomt.');
  if (state.packageName.length > 90) errors.push('Pakkenavn kan ikke være lengre enn 90 tegn.');
  if (/[\r\n]/.test(state.packageName)) errors.push('Pakkenavn kan ikke inneholde linjeskift.');
  for (const field of recipe.fields) {
    const value = params[field.id];
    if (field.type === 'number') {
      if (!Number.isFinite(Number(value))) errors.push(`${field.label} må være et tall.`);
      if (field.min !== undefined && Number(value) < field.min) errors.push(`${field.label} må være minst ${field.min}.`);
      if (field.max !== undefined && Number(value) > field.max) errors.push(`${field.label} kan ikke være høyere enn ${field.max}.`);
    }
  }
  if (recipe.id === 'disk-space' && !/^[A-Za-z]:$/.test(String(params.drive || ''))) errors.push('Disk må skrives som C: eller D:.');
  if (typeof recipe.validate === 'function') errors.push(...recipe.validate(params));
  return errors;
}

function generateScripts(showToast = true) {
  const recipe = currentRecipe();
  const packageInput = $('field-packageName');
  if (packageInput) state.packageName = packageInput.value;
  const params = readFormValues($('configForm'), recipe.fields, 'field');
  state.recipeValues[recipe.id] = params;
  const errors = validateParams(recipe, params);
  if (errors.length) {
    renderConfigWarnings(errors.map((text) => ({ type: 'bad', text })));
    setBuilderStatus('bad', 'Kan ikke generere scripts', errors[0]);
    if (showToast) toast(errors[0], 'bad');
    return false;
  }

  const generated = recipe.generate(params, getMeta(), recipe);
  state.detection = generated.detection.trimEnd() + '\n';
  state.remediation = generated.remediation.trimEnd() + '\n';
  $('detectionScript').value = state.detection;
  $('remediationScript').value = state.remediation;
  state.configDirty = false;
  state.scriptDirty = false;
  updateScriptMeta();
  renderConfigWarnings();
  updateBuilderStatus();
  renderValidation();
  renderTestForm();
  updatePackageSummary();
  if (showToast) toast('Begge scriptfilene er generert.', 'good');
  return true;
}

function recipeWarnings(recipe, params, meta) {
  const warnings = [];
  if (recipe.id === 'bitlocker' && params.bitlockerAction === 'enable') {
    warnings.push({ type: 'warn', text: 'Aktivering av BitLocker kan påvirke oppstart og nøkkelhåndtering. Bekreft TPM, recovery key escrow og eksisterende Intune-policy før produksjon.' });
  }
  if (recipe.id === 'onedrive' && !meta.runAsUser) warnings.push({ type: 'bad', text: 'OneDrive-oppskriften bør kjøres med pålogget bruker. SYSTEM har ikke riktig brukerprofil.' });
  if (recipe.id === 'teams-cache') {
    if (!meta.runAsUser) warnings.push({ type: 'bad', text: 'Teams-cache ligger i brukerprofilen. Velg pålogget bruker for at scriptet skal treffe riktig profil.' });
    if (params.closeTeams) warnings.push({ type: 'warn', text: 'Remediation stopper Teams-prosessen og kan avbryte en aktiv økt.' });
  }
  if (recipe.id === 'printers' && params.clearStaleJobs) warnings.push({ type: 'warn', text: 'Gamle filer i utskriftskøen slettes. Verifiser tidsgrensen og test med deres skriverplattform.' });
  if (recipe.id === 'defender') warnings.push({ type: 'info', text: 'Tamper Protection, passiv modus eller tredjeparts antivirus kan hindre lokale endringer.' });
  if (recipe.id === 'registry') {
    if (params.hive === 'HKCU' && !meta.runAsUser) warnings.push({ type: 'bad', text: 'HKCU bør normalt kjøres med pålogget brukerkontekst. SYSTEM skriver til en annen brukerhive.' });
    if (params.hive === 'HKLM' && meta.runAsUser) warnings.push({ type: 'warn', text: 'HKLM krever vanligvis administratorrettigheter. SYSTEM-kontekst anbefales.' });
  }
  if (recipe.id === 'services' && params.startupType === 'Disabled' && params.expectedStatus === 'Running') warnings.push({ type: 'warn', text: 'Disabled og Running er motstridende. Builderen bruker Stopped når oppstartstype er Disabled.' });
  if (recipe.id === 'custom') warnings.push({ type: 'bad', text: 'Egendefinert-malene inneholder TODO-logikk og er ikke produksjonsklare før de er erstattet og testet.' });
  if (meta.signatureCheck) warnings.push({ type: 'info', text: 'Ved håndhevet signaturkontroll må scriptet være signert av en sertifikatutsteder enheten stoler på. Filene lastes ned i UTF-8 uten BOM.' });
  return warnings;
}

function renderConfigWarnings(override) {
  const recipe = currentRecipe();
  const params = state.recipeValues[recipe.id] || defaultValues(recipe);
  const warnings = override || recipeWarnings(recipe, params, getMeta());
  const container = $('configWarnings');
  container.innerHTML = '';
  for (const warning of warnings) {
    const item = document.createElement('div');
    item.className = `config-warning ${warning.type}`;
    const icon = document.createElement('span');
    icon.textContent = warning.type === 'bad' ? '!' : warning.type === 'warn' ? '△' : 'i';
    const text = document.createElement('span');
    text.textContent = warning.text;
    item.append(icon, text);
    container.appendChild(item);
  }
}

function setBuilderStatus(type, title, text) {
  $('builderStatusDot').className = `status-dot ${type}`;
  $('builderStatusTitle').textContent = title;
  $('builderStatusText').textContent = text;
}

function updateBuilderStatus() {
  if (state.configDirty) {
    setBuilderStatus('warn', 'Konfigurasjonen er endret', 'Trykk «Generer scripts» for å bruke de nye verdiene.');
  } else if (state.scriptDirty) {
    setBuilderStatus('warn', 'Scripts er manuelt redigert', 'Validering og nedlasting bruker teksten som står i editorene.');
  } else {
    setBuilderStatus('good', 'Scripts er klare', `${currentRecipe().name} er generert og klar for testing.`);
  }
}

function updateScriptMeta() {
  state.detection = $('detectionScript').value;
  state.remediation = $('remediationScript').value;
  const detectionBytes = encoder.encode(state.detection).length;
  const remediationBytes = encoder.encode(state.remediation).length;
  $('detectionLines').textContent = `${state.detection.split(/\r?\n/).length} linjer`;
  $('remediationLines').textContent = `${state.remediation.split(/\r?\n/).length} linjer`;
  $('detectionBytes').textContent = formatBytes(detectionBytes);
  $('remediationBytes').textContent = formatBytes(remediationBytes);
}

function resetTestConsole() {
  $('testConsole').innerHTML = '<span class="console-muted">Velg testverdier og trykk «Test detection».</span>';
  $('exitResult').className = 'exit-result neutral';
  $('exitResult').querySelector('strong').textContent = '–';
  $('exitResult').querySelector('p').textContent = 'Ingen test kjørt ennå';
}

function runSimulation() {
  const recipe = currentRecipe();
  const params = state.recipeValues[recipe.id] || defaultValues(recipe);
  const test = readFormValues($('testForm'), recipe.testFields, 'test');
  state.testValues[recipe.id] = test;
  const result = recipe.simulate(params, test);
  const consoleElement = $('testConsole');
  consoleElement.innerHTML = '';
  const lines = [
    { type: 'prompt', text: `PS> Simulate-Detection -Recipe "${recipe.name}"` },
    { type: 'info', text: `Oppskrift: ${recipe.name}` },
    { type: 'info', text: `Pakkenavn: ${state.packageName || recipe.defaultPackage}` },
    ...result.details.map((text) => ({ type: 'info', text })),
    { type: result.exitCode === 0 ? 'success' : 'warn', text: result.message },
    { type: result.exitCode === 0 ? 'success' : 'warn', text: `Process finished with exit code ${result.exitCode}` }
  ];
  for (const line of lines) {
    const span = document.createElement('span');
    span.className = `console-line ${line.type}`;
    span.textContent = line.text;
    consoleElement.appendChild(span);
  }

  const exit = $('exitResult');
  exit.className = `exit-result ${result.exitCode === 0 ? 'success' : result.exitCode === 1 ? 'issue' : 'error'}`;
  exit.querySelector('strong').textContent = String(result.exitCode);
  exit.querySelector('p').textContent = result.exitCode === 0 ? 'Ingen remediation kjøres' : result.exitCode === 1 ? 'Remediation.ps1 ville blitt startet' : 'Ingen automatisk remediation';
}

function scanBalance(text) {
  const stack = [];
  const pairs = { ')': '(', ']': '[', '}': '{' };
  let mode = 'code';
  for (let i = 0; i < text.length; i += 1) {
    const char = text[i];
    const next = text[i + 1];
    if (mode === 'lineComment') {
      if (char === '\n') mode = 'code';
      continue;
    }
    if (mode === 'blockComment') {
      if (char === '#' && next === '>') { mode = 'code'; i += 1; }
      continue;
    }
    if (mode === 'single') {
      if (char === "'" && next === "'") { i += 1; continue; }
      if (char === "'") mode = 'code';
      continue;
    }
    if (mode === 'double') {
      if (char === '`') { i += 1; continue; }
      if (char === '"') mode = 'code';
      continue;
    }
    if (char === '#' && next === '>') continue;
    if (char === '<' && next === '#') { mode = 'blockComment'; i += 1; continue; }
    if (char === '#') { mode = 'lineComment'; continue; }
    if (char === "'") { mode = 'single'; continue; }
    if (char === '"') { mode = 'double'; continue; }
    if ('([{'.includes(char)) stack.push(char);
    if (')]}'.includes(char)) {
      if (stack.pop() !== pairs[char]) return false;
    }
  }
  return mode !== 'single' && mode !== 'double' && mode !== 'blockComment' && stack.length === 0;
}

function maxStaticOutputLength(text) {
  let max = 0;
  const regex = /Write-Output\s+(?:\(\s*)?["']([^"'\r\n]{0,5000})["']/gi;
  let match;
  while ((match = regex.exec(text))) max = Math.max(max, match[1].length);
  return max;
}

function getValidationResults() {
  const detection = $('detectionScript').value;
  const remediation = $('remediationScript').value;
  const combined = `${detection}\n${remediation}`;
  const secretPattern = /(?:password|passwd|secret|api[_-]?key|access[_-]?token)\s*=\s*["'][^"']+["']/i;
  const rebootPattern = /\b(?:Restart-Computer|Stop-Computer|shutdown(?:\.exe)?\s+(?:\/r|-r)|reboot)\b/i;
  const maxOutput = Math.max(maxStaticOutputLength(detection), maxStaticOutputLength(remediation));
  return [
    { pass: /\bexit\s+0\b/i.test(detection), title: 'Detection har exit 0', detail: 'Brukes når ønsket tilstand er oppfylt.' },
    { pass: /\bexit\s+1\b/i.test(detection), title: 'Detection har exit 1', detail: 'Kreves for at Intune skal starte remediation.' },
    { pass: /\bWrite-Output\b/i.test(detection), title: 'Detection skriver resultat', detail: 'Kort output gjør feilsøking i Intune enklere.' },
    { pass: remediation.trim().length > 80 && /\bWrite-Output\b/i.test(remediation), title: 'Remediation er definert', detail: 'Scriptet har både handling og rapportering.' },
    { pass: !rebootPattern.test(combined), title: 'Ingen restartkommandoer', detail: 'Microsoft fraråder reboot-kommandoer i Remediations.' },
    { pass: !secretPattern.test(combined), title: 'Ingen åpenbare hemmeligheter', detail: 'Passord, tokens og nøkler skal ikke ligge i scripts.' },
    { pass: scanBalance(detection) && scanBalance(remediation) && maxOutput < 2048, title: 'Struktur og output ser trygg ut', detail: `Parenteser og klammer er balansert. Lengste statiske output er ${maxOutput} tegn.` }
  ];
}

function renderValidation() {
  const results = getValidationResults();
  const list = $('validationList');
  list.innerHTML = '';
  const passed = results.filter((result) => result.pass).length;
  $('validationScore').textContent = `${passed}/${results.length}`;
  $('validationScore').className = `validation-score ${passed === results.length ? 'good' : passed >= results.length - 2 ? 'warn' : ''}`;
  for (const result of results) {
    const item = document.createElement('div');
    item.className = `validation-item ${result.pass ? 'pass' : 'fail'}`;
    const icon = document.createElement('span');
    icon.className = 'validation-icon';
    icon.textContent = result.pass ? '✓' : '!';
    const text = document.createElement('div');
    const title = document.createElement('strong');
    title.textContent = result.title;
    const detail = document.createElement('p');
    detail.textContent = result.detail;
    text.append(title, detail);
    item.append(icon, text);
    list.appendChild(item);
  }
}

function localTestRunner() {
  return [
    '#requires -Version 5.1',
    '<#',
    '.SYNOPSIS',
    '    Kjører Detection.ps1 lokalt og viser exit code.',
    '.NOTES',
    '    Kjør i en PowerShell-konsoll med samme bruker- eller SYSTEM-kontekst som planlagt i Intune.',
    '#>',
    '',
    "$detectionPath = Join-Path $PSScriptRoot 'Detection.ps1'",
    'if (-not (Test-Path $detectionPath)) {',
    '    Write-Error "Detection.ps1 ble ikke funnet i samme mappe."',
    '    exit 2',
    '}',
    '',
    "$windowsPowerShell = Join-Path $env:SystemRoot 'System32\\WindowsPowerShell\\v1.0\\powershell.exe'",
    '& $windowsPowerShell -NoProfile -ExecutionPolicy Bypass -File $detectionPath',
    '$exitCode = $LASTEXITCODE',
    '',
    'Write-Host ""',
    'switch ($exitCode) {',
    '    0 { Write-Host "Exit 0: Ingen avvik. Remediation ville ikke blitt kjørt." -ForegroundColor Green }',
    '    1 { Write-Host "Exit 1: Avvik funnet. Intune ville startet Remediation.ps1." -ForegroundColor Yellow }',
    '    default { Write-Host "Exit $exitCode: Ingen automatisk remediation i Intune." -ForegroundColor Red }',
    '}',
    '',
    'exit $exitCode'
  ].join('\n') + '\n';
}

function localTestCommand() {
  return 'powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\\Detection.ps1; Write-Host "Exit code: $LASTEXITCODE"';
}

function packageReadme() {
  const recipe = currentRecipe();
  const meta = getMeta();
  const params = state.recipeValues[recipe.id] || defaultValues(recipe);
  const warnings = recipeWarnings(recipe, params, meta).map((warning) => `- ${warning.text}`);
  return [
    'INTUNE REMEDIATION BUILDER',
    '===========================',
    '',
    `Pakkenavn: ${meta.packageName}`,
    `Oppskrift: ${recipe.name}`,
    `Beskrivelse: ${recipe.description}`,
    `Generert: ${new Date().toLocaleString('nb-NO')}`,
    '',
    'FILER',
    '-----',
    '- Detection.ps1',
    '- Remediation.ps1',
    '- Test-Detection.ps1',
    '- manifest.json',
    '',
    'ANBEFALTE INTUNE-INNSTILLINGER',
    '------------------------------',
    `- Kjør med pålogget bruker: ${meta.runAsUser ? 'Ja' : 'Nei (SYSTEM)'}`,
    `- Kjør i 64-bit PowerShell: ${meta.run64Bit ? 'Ja' : 'Nei'}`,
    `- Håndhev scriptsignatur: ${meta.signatureCheck ? 'Ja' : 'Nei'}`,
    `- Anbefalt frekvens: ${scheduleLabels[meta.schedule] || meta.schedule}`,
    '',
    'OPPLASTING I INTUNE',
    '-------------------',
    '1. Åpne Microsoft Intune admin center.',
    '2. Gå til Devices > Manage devices > Scripts and remediations.',
    '3. Velg Create script package.',
    '4. Last opp Detection.ps1 og Remediation.ps1.',
    '5. Bruk anbefalte innstillinger ovenfor og tildel først til en testgruppe.',
    '',
    'LOKAL TEST',
    '----------',
    'Kjør Test-Detection.ps1 eller bruk:',
    localTestCommand(),
    '',
    'EXIT CODES',
    '----------',
    '- 0: Ingen avvik. Remediation kjøres ikke.',
    '- 1: Avvik funnet. Intune starter Remediation.ps1.',
    '- Andre: Remediation startes ikke automatisk.',
    '',
    'VIKTIG',
    '------',
    '- Test scriptparet på en avgrenset Windows-enhet før produksjon.',
    '- Scriptoutput i Intune kan maksimalt være 2 048 tegn.',
    '- Ikke legg restartkommandoer, passord, tokens, persondata eller andre hemmeligheter i scriptet.',
    '- Scriptfilene i denne pakken er kodet i UTF-8 uten BOM.',
    ...(warnings.length ? ['', 'OPPSKRIFTSSPESIFIKKE MERKNADER', '---------------------------', ...warnings] : []),
    '',
    'Generert script er et utgangspunkt og må kvalitetssikres i organisasjonens miljø.'
  ].join('\r\n');
}

function packageManifest() {
  const recipe = currentRecipe();
  const meta = getMeta();
  return JSON.stringify({
    schemaVersion: 1,
    generator: 'Intune Remediation Builder',
    generatedAt: new Date().toISOString(),
    package: {
      name: meta.packageName,
      recipeId: recipe.id,
      recipeName: recipe.name,
      description: recipe.description
    },
    intuneSettings: {
      runAsLoggedOnUser: meta.runAsUser,
      runIn64BitPowerShell: meta.run64Bit,
      enforceSignatureCheck: meta.signatureCheck,
      recommendedSchedule: meta.schedule
    },
    files: ['Detection.ps1', 'Remediation.ps1', 'Test-Detection.ps1', 'README.txt']
  }, null, 2);
}

function updatePackageSummary() {
  const meta = getMeta();
  const recipe = currentRecipe();
  const summary = $('packageSummary');
  summary.innerHTML = '';
  const entries = [
    ['Pakkenavn', meta.packageName],
    ['Oppskrift', recipe.name],
    ['Kontekst', meta.runAsUser ? 'Pålogget bruker' : 'SYSTEM'],
    ['64-bit', meta.run64Bit ? 'Ja' : 'Nei'],
    ['Frekvens', scheduleLabels[meta.schedule] || meta.schedule]
  ];
  for (const [term, description] of entries) {
    const dt = document.createElement('dt');
    dt.textContent = term;
    const dd = document.createElement('dd');
    dd.textContent = description;
    summary.append(dt, dd);
  }
}

function downloadText(filename, content) {
  const blob = new Blob([content], { type: 'text/plain;charset=utf-8' });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = filename;
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

function copyText(text, successMessage) {
  const fallback = () => {
    const textarea = document.createElement('textarea');
    textarea.value = text;
    textarea.style.position = 'fixed';
    textarea.style.opacity = '0';
    document.body.appendChild(textarea);
    textarea.select();
    const ok = document.execCommand('copy');
    textarea.remove();
    if (!ok) throw new Error('Kunne ikke kopiere.');
  };

  const promise = navigator.clipboard?.writeText ? navigator.clipboard.writeText(text) : Promise.resolve().then(fallback);
  promise.then(() => toast(successMessage, 'good')).catch(() => {
    try { fallback(); toast(successMessage, 'good'); } catch { toast('Kunne ikke kopiere til utklippstavlen.', 'bad'); }
  });
}

let crcTable = null;
function getCrcTable() {
  if (crcTable) return crcTable;
  crcTable = new Uint32Array(256);
  for (let n = 0; n < 256; n += 1) {
    let c = n;
    for (let k = 0; k < 8; k += 1) c = (c & 1) ? (0xedb88320 ^ (c >>> 1)) : (c >>> 1);
    crcTable[n] = c >>> 0;
  }
  return crcTable;
}

function crc32(bytes) {
  const table = getCrcTable();
  let crc = 0xffffffff;
  for (const byte of bytes) crc = table[(crc ^ byte) & 0xff] ^ (crc >>> 8);
  return (crc ^ 0xffffffff) >>> 0;
}

function le16(value) {
  return new Uint8Array([value & 0xff, (value >>> 8) & 0xff]);
}
function le32(value) {
  return new Uint8Array([value & 0xff, (value >>> 8) & 0xff, (value >>> 16) & 0xff, (value >>> 24) & 0xff]);
}
function concatBytes(parts) {
  const length = parts.reduce((sum, part) => sum + part.length, 0);
  const output = new Uint8Array(length);
  let offset = 0;
  for (const part of parts) { output.set(part, offset); offset += part.length; }
  return output;
}
function dosDateTime(date = new Date()) {
  const year = Math.max(1980, date.getFullYear());
  const time = (date.getHours() << 11) | (date.getMinutes() << 5) | Math.floor(date.getSeconds() / 2);
  const day = ((year - 1980) << 9) | ((date.getMonth() + 1) << 5) | date.getDate();
  return { time, day };
}

function createZip(files) {
  const locals = [];
  const centrals = [];
  let offset = 0;
  const stamp = dosDateTime();

  for (const file of files) {
    const name = encoder.encode(file.name);
    const data = typeof file.content === 'string' ? encoder.encode(file.content) : file.content;
    const crc = crc32(data);
    const localHeader = concatBytes([
      le32(0x04034b50), le16(20), le16(0x0800), le16(0), le16(stamp.time), le16(stamp.day),
      le32(crc), le32(data.length), le32(data.length), le16(name.length), le16(0), name
    ]);
    locals.push(localHeader, data);

    const centralHeader = concatBytes([
      le32(0x02014b50), le16(20), le16(20), le16(0x0800), le16(0), le16(stamp.time), le16(stamp.day),
      le32(crc), le32(data.length), le32(data.length), le16(name.length), le16(0), le16(0), le16(0), le16(0),
      le32(0), le32(offset), name
    ]);
    centrals.push(centralHeader);
    offset += localHeader.length + data.length;
  }

  const centralDirectory = concatBytes(centrals);
  const end = concatBytes([
    le32(0x06054b50), le16(0), le16(0), le16(files.length), le16(files.length),
    le32(centralDirectory.length), le32(offset), le16(0)
  ]);
  return new Blob([concatBytes([...locals, centralDirectory, end])], { type: 'application/zip' });
}


function ensureScriptsCurrent() {
  if (state.configDirty && !generateScripts(false)) return false;
  updateScriptMeta();
  return true;
}

function downloadPackage() {
  if (!ensureScriptsCurrent()) {
    toast('Rett konfigurasjonsfeil før nedlasting.', 'bad');
    return;
  }
  const recipe = currentRecipe();
  const packageName = sanitizeFilePart(state.packageName || recipe.defaultPackage);
  const zip = createZip([
    { name: 'Detection.ps1', content: state.detection },
    { name: 'Remediation.ps1', content: state.remediation },
    { name: 'Test-Detection.ps1', content: localTestRunner() },
    { name: 'README.txt', content: packageReadme() },
    { name: 'manifest.json', content: packageManifest() }
  ]);
  const url = URL.createObjectURL(zip);
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = `${packageName}.zip`;
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
  toast('Komplett Intune-pakke er lastet ned.', 'good');
}

function toast(message, type = 'good') {
  const element = $('toast');
  element.textContent = message;
  element.className = `toast ${type} show`;
  clearTimeout(state.toastTimer);
  state.toastTimer = setTimeout(() => { element.className = 'toast'; }, 2600);
}

function handleDownload(type) {
  if (!ensureScriptsCurrent()) {
    toast('Rett konfigurasjonsfeil før nedlasting.', 'bad');
    return;
  }
  if (type === 'detection') downloadText('Detection.ps1', state.detection);
  if (type === 'remediation') downloadText('Remediation.ps1', state.remediation);
  toast(`${type === 'detection' ? 'Detection.ps1' : 'Remediation.ps1'} er lastet ned.`, 'good');
}

function bindEvents() {
  $('quickRecipe').addEventListener('change', () => {
    const recipe = recipes.find((item) => item.id === $('quickRecipe').value);
    if (recipe) $('quickPackageName').value = recipe.defaultPackage;
  });
  $('quickPackageName').addEventListener('input', () => {
    state.packageName = $('quickPackageName').value;
    const builderInput = $('field-packageName');
    if (builderInput) builderInput.value = state.packageName;
    state.configDirty = true;
    updateBuilderStatus();
    updatePackageSummary();
  });
  $('quickStart').addEventListener('click', () => activateRecipe($('quickRecipe').value, { packageName: $('quickPackageName').value, reset: true, scroll: true }));
  $('recipeSearch').addEventListener('input', () => renderRecipeGrid($('recipeSearch').value));
  $('recipeGrid').addEventListener('click', (event) => {
    const card = event.target.closest('[data-recipe]');
    if (!card) return;
    activateRecipe(card.dataset.recipe, { reset: true, scroll: true });
  });
  $('generateScripts').addEventListener('click', () => generateScripts(true));
  $('resetRecipe').addEventListener('click', () => {
    const recipe = currentRecipe();
    activateRecipe(recipe.id, { reset: true, packageName: recipe.defaultPackage });
    toast('Oppskriften er tilbakestilt.', 'good');
  });
  ['runAsUser', 'run64Bit', 'signatureCheck', 'schedule'].forEach((id) => {
    $(id).addEventListener('change', () => {
      state.configDirty = true;
      updateBuilderStatus();
      renderConfigWarnings();
      updatePackageSummary();
    });
  });
  $('detectionScript').addEventListener('input', () => {
    state.scriptDirty = true;
    state.configDirty = false;
    updateScriptMeta();
    updateBuilderStatus();
    renderValidation();
  });
  $('remediationScript').addEventListener('input', () => {
    state.scriptDirty = true;
    state.configDirty = false;
    updateScriptMeta();
    updateBuilderStatus();
    renderValidation();
  });
  document.addEventListener('click', (event) => {
    const copyButton = event.target.closest('[data-copy]');
    if (copyButton) {
      if (!ensureScriptsCurrent()) {
        toast('Rett konfigurasjonsfeil før kopiering.', 'bad');
        return;
      }
      const type = copyButton.dataset.copy;
      copyText(type === 'detection' ? state.detection : state.remediation, `${type === 'detection' ? 'Detection.ps1' : 'Remediation.ps1'} er kopiert.`);
      return;
    }
    const downloadButton = event.target.closest('[data-download]');
    if (downloadButton) handleDownload(downloadButton.dataset.download);
  });
  $('runTest').addEventListener('click', runSimulation);
  $('copyTestCommand').addEventListener('click', () => copyText(localTestCommand(), 'Lokal testkommando er kopiert.'));
  $('downloadRunner').addEventListener('click', () => {
    downloadText('Test-Detection.ps1', localTestRunner());
    toast('Test-Detection.ps1 er lastet ned.', 'good');
  });
  $('downloadPackage').addEventListener('click', downloadPackage);
}

function initialize() {
  renderQuickRecipeOptions();
  renderRecipeGrid();
  bindEvents();
  activateRecipe('defender', { reset: true, packageName: 'Kontroller Microsoft Defender' });
}

document.addEventListener('DOMContentLoaded', initialize);
