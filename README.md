# Intune Remediation Builder

En statisk, norskspråklig webapp som genererer sammenhørende PowerShell-scripts for Microsoft Intune Remediations:

- `Detection.ps1`
- `Remediation.ps1`
- `Test-Detection.ps1`
- manifest og README i en nedlastbar ZIP-pakke

Appen kjører helt lokalt i nettleseren og krever ingen backend, konto eller API-nøkkel.

## 17 inkluderte oppskrifter

### Opprinnelige builder-oppskrifter

- BitLocker
- OneDrive
- Windows Update
- Printere / Print Spooler
- Microsoft Teams-cache
- Microsoft Defender
- Diskplass
- Windows-tjenester
- Registry-innstillinger
- Egendefinert PowerShell-mal

### Nye oppskrifter basert på de opplastede PowerShell-filene

- **Lokal IP for feltteknikere** – kontrollerer den påloggede brukeren mot den lokale gruppen `Network Configuration Operators` og legger brukeren til ved avvik. Scriptet setter ikke en IP-adresse; det tildeler lokale nettverkskonfigurasjonsrettigheter.
- **Jabra Direct – automatisk oppdatering** – finner installert versjon i register/programfiler, leser siste versjon fra Jabra release notes, bruker fallback ved feil og kjører stille oppgradering fra leverandørens installer.
- **Wi-Fi-nettverkskategori** – kontrollerer eksakte SSID-/profilnavn i aktive og bufrede Windows-profiler og setter dem til `Private`. SSID-er kan tilpasses i appen.
- **Adobe Reader – deaktiver Flash** – håndhever `bEnableFlash=0` i maskinpolicyen.
- **Adobe Acrobat – deaktiver JavaScript** – håndhever `bDisableJavaScript=1` for fullversjonen Adobe Acrobat DC.
- **Adobe Reader – deaktiver JavaScript** – håndhever `bDisableJavaScript=1` for Acrobat Reader DC.
- **Fjern Intel PROSet/Wireless** – oppdager matchende uninstall-oppføringer, kjører registrert MSI-/EXE-avinstallasjon og bekrefter resultatet.

Hver opplastede oppskrift viser i brukergrensesnittet:

- hva `Detection.ps1` undersøker
- hva som gir `exit 0` eller `exit 1`
- hvilke handlinger `Remediation.ps1` utfører
- viktige begrensninger og risikoer fra den faktiske scriptlogikken
- navnene på de opprinnelige kildefilene

## Viktige observasjoner fra de opplastede scriptfilene

- Lokal-IP-scriptet gir gruppemedlemskap; det konfigurerer ingen konkret IP-adresse.
- Jabra-scriptet har `InstallIfMissing = $false` som standard. En maskin uten Jabra Direct regnes derfor som compliant med mindre valget aktiveres i builderen.
- Wi-Fi-scriptet regner en maskin uten samsvarende profil som compliant. Detection markerer `DomainAuthenticated` som avvik, mens remediation hopper over denne kategorien. Appen viser en advarsel om dette.
- Adobe-scriptparene oppretter og håndhever maskinpolicyer selv om den aktuelle Adobe-applikasjonen ikke er installert.
- Intel PROSet-scriptet legger generiske `/quiet /norestart`-parametere til EXE-avinstallatører. Disse må testes mot de faktiske pakkeversjonene.

## Funksjoner

- Dynamiske `Detection.ps1`- og `Remediation.ps1`-editorer
- Simulert **Test detection** for hver oppskrift
- Forklaring av exit codes
- Statisk kvalitetssjekk av scripts, inkludert både `Write-Output` og `Write-Host`
- Kopiering og separat nedlasting
- Komplett ZIP-pakke i UTF-8 uten BOM
- Anbefalte Intune-innstillinger per oppskrift
- Beskrivelse og arbeidsflyt for opplastede scriptpar
- Responsivt design som matcher DomainGuard-stilen
- Vipps-støtteknapp på 20 kr

## Viktig om Test detection

En vanlig nettleser kan ikke kjøre PowerShell på den lokale Windows-maskinen. Testfunksjonen i appen simulerer oppskriftens logikk med valgte testverdier og kontrollerer scriptstrukturen.

Den nedlastbare `Test-Detection.ps1`-filen kan brukes på en Windows-testmaskin for å kjøre den faktiske `Detection.ps1`-filen og vise exit code.

## Publiser på GitHub Pages

1. Opprett et nytt GitHub-repository.
2. Pakk ut ZIP-filen.
3. Last opp innholdet i mappen til repository-roten:
   - `index.html`
   - `styles.css`
   - `app.js`
   - `.nojekyll`
   - `README.md`
4. Commit til `main`.
5. Åpne **Settings → Pages**.
6. Velg **Deploy from a branch**.
7. Velg **main** og **/(root)**.
8. Lagre.

Appen bruker bare relative filstier og fungerer både på et hoveddomene og under en GitHub Pages-prosjektsti.

## Lokal kjøring

```bash
python3 -m http.server 8080
```

Åpne deretter `http://localhost:8080`.

## Sikkerhet og ansvar

De opplastede scriptparene er gjengitt og parameterisert etter innholdet i filene. De er ikke automatisk sikkerhetsgodkjent. Test alltid på en avgrenset enhetsgruppe, kontroller kjøringskontekst, nettverkstilgang, avinstalleringsparametere og konsekvensene i eget miljø før bred utrulling.
