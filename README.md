# Intune Remediation Builder

En statisk, norskspråklig webapp som lager sammenhørende PowerShell-scripts for Microsoft Intune Remediations:

- `Detection.ps1`
- `Remediation.ps1`
- `Test-Detection.ps1`
- `manifest.json`
- en lokal README i den nedlastbare ZIP-pakken

Appen kjører helt lokalt i nettleseren og krever ingen backend, konto eller API-nøkkel.

## Microsoft-kilder for ASR

- [ASR rules overview](https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-overview)
- [Configure ASR rules and exclusions](https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-configure)
- [ASR rules deployment guide](https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-deployment)
- [Manage attack surface reduction settings with Microsoft Intune](https://learn.microsoft.com/en-us/intune/intune-service/protect/endpoint-security-asr-policy)

## Sikkerhet og ansvar

Alle scripts er utgangspunkt som må testes og kvalitetssikres i eget miljø. Start med en avgrenset testgruppe, verifiser kjøringskontekst, policykonflikter, lisenskrav, nettverkstilgang og påvirkning på forretningskritiske applikasjoner før bred utrulling.
