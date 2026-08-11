# Intune Remediation Builder

En statisk, norskspråklig webapp som lager sammenhørende PowerShell-scripts for Microsoft Intune Remediations:

- `Detection.ps1`
- `Remediation.ps1`
- `Test-Detection.ps1`
- `manifest.json`
- en lokal README i den nedlastbare ZIP-pakken

Appen kjører helt lokalt i nettleseren og krever ingen backend, konto eller API-nøkkel.

## Nytt i denne versjonen

- **Kategorifilter** for Alle, Sikkerhet, Bruker, Vedlikehold, Tjenester, Konfigurasjon, Tilgang, Programvare, Nettverk og Avansert.
- Når for eksempel **Sikkerhet** velges, vises bare oppskrifter i kategorien Sikkerhet.
- Egen horisontal rad for **Defender-anbefalinger**.
- Tre nye Defender-/ASR-oppskrifter.
- Komplett norsk referanse for **alle 19 ASR-regler**, med GUID, kategori, anbefalt første modus og viktige utrullingsmerknader.
- Stegvis veiledning for oppsett i Microsoft Intune Endpoint Security.
- ASR-søk og egne ASR-kategorifiltre.

## 20 inkluderte oppskrifter

### Sikkerhet

- BitLocker
- Microsoft Defender
- **Defender anbefalt grunnbeskyttelse**
- **ASR – standardbeskyttelse**
- **ASR – pilot for alle regler**
- Adobe Reader – deaktiver Flash
- Adobe Acrobat – deaktiver JavaScript
- Adobe Reader – deaktiver JavaScript

### Bruker

- OneDrive
- Microsoft Teams-cache

### Vedlikehold

- Windows Update
- Diskplass

### Tjenester

- Printere / Print Spooler
- Windows-tjenester

### Konfigurasjon

- Registry-innstillinger

### Tilgang

- Lokal IP for feltteknikere

### Programvare

- Jabra Direct – automatisk oppdatering
- Fjern Intel PROSet/Wireless

### Nettverk

- Wi-Fi-nettverkskategori

### Avansert

- Egendefinert PowerShell-mal

## Defender-anbefalinger

Den egne Defender-raden samler fire oppskrifter:

1. **Microsoft Defender** – kontrollerer antivirus, sanntidsbeskyttelse og signaturalder.
2. **Defender anbefalt grunnbeskyttelse** – kontrollerer blant annet skylevert beskyttelse, PUA-beskyttelse, nettverksbeskyttelse, atferdsovervåking, IOAV og signaturer.
3. **ASR – standardbeskyttelse** – konfigurerer de tre standardbeskyttelsesreglene i Block eller Audit.
4. **ASR – pilot for alle regler** – konfigurerer hele ASR-regelsettet i Audit som standard, med mulighet for Block etter testing.

PowerShell-oppskriftene bruker lokale Microsoft Defender-cmdleter. I produksjon anbefales Intune Endpoint Security-policy som autoritativ konfigurasjonsmetode. Lokale `Set-MpPreference`- og `Add-MpPreference`-innstillinger har lavere prioritet enn policy og kan bli overskrevet.

## ASR-guiden

Appen har en egen seksjon med:

- alle 19 gjeldende ASR-regler
- norske forklaringer
- Microsoft Intune-navn
- regel-GUID-er med kopieringsknapp
- kategorier
- markering av de tre standardbeskyttelsesreglene
- informasjon om Warn-støtte
- særmerknader for WMI, LSASS, Office-kodeinjeksjon og serverregelen
- modusene `0`, `1`, `2`, `5` og `6`
- anbefalt utrullingsløp fra Audit til Warn/Block
- oppsett i **Endpoint security → Attack surface reduction**

### Anbefalt ASR-utrulling

1. Opprett en Intune Endpoint Security-policy med plattform **Windows** og profil **Attack Surface Reduction Rules**.
2. Tildel policyen til Microsoft Entra-enhetsgrupper, ikke brukergrupper.
3. Standardbeskyttelsesreglene kan normalt settes til Block, men WMI-regelen må testes ekstra grundig når Configuration Manager brukes.
4. Sett de øvrige reglene til Audit på en liten pilotring.
5. Analyser ASR-rapportering, Advanced Hunting og relevante Windows-hendelser.
6. Lag presise unntak per regel der det er mulig.
7. Flytt reglene kontrollert til Warn eller Block og utvid utrullingsringene gradvis.

## Opplastede PowerShell-oppskrifter

Følgende oppskrifter er basert på scriptpar som ble levert til prosjektet:

- **Lokal IP for feltteknikere** – kontrollerer den påloggede brukeren mot den lokale gruppen `Network Configuration Operators` og legger brukeren til ved avvik. Scriptet setter ikke en IP-adresse; det tildeler lokale nettverkskonfigurasjonsrettigheter.
- **Jabra Direct – automatisk oppdatering** – finner installert versjon i register/programfiler, leser siste versjon fra Jabra release notes, bruker fallback ved feil og kjører stille oppgradering fra leverandørens installer.
- **Wi-Fi-nettverkskategori** – kontrollerer eksakte SSID-/profilnavn i aktive og bufrede Windows-profiler og setter dem til `Private`.
- **Adobe Reader – deaktiver Flash** – håndhever `bEnableFlash=0` i maskinpolicyen.
- **Adobe Acrobat – deaktiver JavaScript** – håndhever `bDisableJavaScript=1` for Adobe Acrobat DC.
- **Adobe Reader – deaktiver JavaScript** – håndhever `bDisableJavaScript=1` for Acrobat Reader DC.
- **Fjern Intel PROSet/Wireless** – oppdager matchende uninstall-oppføringer, kjører registrert MSI-/EXE-avinstallasjon og bekrefter resultatet.

Hver opplastede oppskrift viser hva Detection undersøker, hva Remediation endrer, relevante begrensninger og navnene på de opprinnelige kildefilene.

## Viktige observasjoner fra de opplastede scriptfilene

- Lokal-IP-scriptet gir gruppemedlemskap; det konfigurerer ingen konkret IP-adresse.
- Jabra-scriptet har `InstallIfMissing = $false` som standard. En maskin uten Jabra Direct regnes derfor som compliant med mindre valget aktiveres.
- Wi-Fi-scriptet regner en maskin uten samsvarende profil som compliant. Detection markerer `DomainAuthenticated` som avvik, mens Remediation hopper over denne kategorien.
- Adobe-scriptparene oppretter og håndhever maskinpolicyer selv om den aktuelle Adobe-applikasjonen ikke er installert.
- Intel PROSet-scriptet legger generiske `/quiet /norestart`-parametere til EXE-avinstallatører. Disse må testes mot de faktiske pakkeversjonene.

## Andre funksjoner

- Dynamiske Detection- og Remediation-editorer
- Simulert **Test detection** for hver oppskrift
- Forklaring av exit codes
- Statisk kvalitetssjekk av scripts
- Kopiering og separat nedlasting
- Komplett ZIP-pakke i UTF-8 uten BOM
- Kategori inkludert i `manifest.json` og pakkens README
- Anbefalte Intune-innstillinger per oppskrift
- Responsivt DomainGuard-inspirert design
- Vipps-støtteknapp på 20 kr

## Viktig om Test detection

En vanlig nettleser kan ikke kjøre PowerShell på Windows-maskinen. Testfunksjonen simulerer oppskriftens logikk og kontrollerer scriptstrukturen.

Den nedlastbare `Test-Detection.ps1` kan brukes på en Windows-testmaskin for å kjøre den faktiske `Detection.ps1`-filen og vise exit code.

## Publiser på GitHub Pages

1. Opprett et GitHub-repository.
2. Pakk ut ZIP-filen.
3. Last opp `index.html`, `styles.css`, `app.js`, `.nojekyll` og `README.md` til repository-roten.
4. Commit til `main`.
5. Åpne **Settings → Pages**.
6. Velg **Deploy from a branch**.
7. Velg **main** og **/(root)**.
8. Lagre.

Appen bruker relative filstier og fungerer både på et hoveddomene og under en GitHub Pages-prosjektsti.

## Lokal kjøring

```bash
python3 -m http.server 8080
```

Åpne deretter `http://localhost:8080`.

## Microsoft-kilder for ASR

- [ASR rules overview](https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-overview)
- [Configure ASR rules and exclusions](https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-configure)
- [ASR rules deployment guide](https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-deployment)
- [Manage attack surface reduction settings with Microsoft Intune](https://learn.microsoft.com/en-us/intune/intune-service/protect/endpoint-security-asr-policy)

## Sikkerhet og ansvar

Alle scripts er utgangspunkt som må testes og kvalitetssikres i eget miljø. Start med en avgrenset testgruppe, verifiser kjøringskontekst, policykonflikter, lisenskrav, nettverkstilgang og påvirkning på forretningskritiske applikasjoner før bred utrulling.
