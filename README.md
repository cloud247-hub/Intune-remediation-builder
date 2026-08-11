# Intune Remediation Builder

En statisk, norskspråklig webapp som genererer sammenhørende PowerShell-scripts for Microsoft Intune Remediations:

- `Detection.ps1`
- `Remediation.ps1`
- `Test-Detection.ps1`
- manifest og README i en nedlastbar ZIP-pakke

Appen kjører helt lokalt i nettleseren og krever ingen backend, konto eller API-nøkkel.

## Ferdige oppskrifter

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

## Funksjoner

- Dynamiske `Detection.ps1`- og `Remediation.ps1`-editorer
- Simulert **Test detection** for hver oppskrift
- Forklaring av exit codes
- Statisk kvalitetssjekk av scripts
- Kopiering og separat nedlasting
- Komplett ZIP-pakke i UTF-8 uten BOM
- Anbefalte Intune-innstillinger per oppskrift
- Responsivt design som matcher DomainGuard-stilen
- Vipps-støtteknapp på 20 kr

## Viktig om Test detection

En vanlig nettleser kan ikke kjøre PowerShell på den lokale Windows-maskinen. Testfunksjonen i appen simulerer oppskriftens logikk med valgte testverdier og kontrollerer scriptstrukturen.

Den nedlastbare `Test-Detection.ps1`-filen kan brukes på en Windows-testmaskin for å kjøre den faktiske `Detection.ps1`-filen og vise exit code.

## Microsoft Intune

Microsoft dokumenterer blant annet følgende krav for Remediations:

- `exit 1` fra detection-scriptet betyr at avvik er funnet og remediation-scriptet skal kjøres.
- Scriptfilene skal være UTF-8.
- Maksimal scriptoutput er 2 048 tegn.
- Reboot-kommandoer skal ikke legges i detection- eller remediation-scripts.
- Scripts skal ikke inneholde passord, hemmeligheter eller persondata.

Dokumentasjon:

https://learn.microsoft.com/en-us/intune/device-management/tools/deploy-remediations

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

Appen bruker bare relative filstier og fungerer derfor både på et hoveddomene og under en GitHub Pages-prosjektsti.

## Lokal kjøring

```bash
python3 -m http.server 8080
```

Åpne deretter:

```text
http://localhost:8080
```

## Sikkerhet og ansvar

Genererte scripts er utgangspunkt, ikke ferdig godkjente produksjonsscripts. Test alltid på en avgrenset enhetsgruppe, kontroller kjøringskontekst og vurder konsekvensene i eget miljø før bred utrulling.
