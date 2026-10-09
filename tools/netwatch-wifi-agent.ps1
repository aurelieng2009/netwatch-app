<#
  Agent Wi-Fi NetWatch : envoie à NetWatch les réseaux Wi-Fi voisins vus par cette machine.
  Usage :   .\netwatch-wifi-agent.ps1 -Url http://<ip-du-serveur>:8484 -Token <jeton>            (boucle)
            .\netwatch-wifi-agent.ps1 -Url ... -Token ... -Once                              (un seul envoi)
  Le jeton se copie depuis NetWatch > Radio. Il ne donne accès qu'au dépôt de scans.
#>
param(
  [Parameter(Mandatory)] [string] $Url,
  [Parameter(Mandatory)] [string] $Token,
  [int] $EveryMinutes = 5,
  [switch] $Once
)
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$endpoint = $Url.TrimEnd('/') + '/api/air/ingest'
do {
  try {
    netsh wlan scan 2>&1 | Out-Null          # demande un balayage frais (sans effet si indisponible)
    Start-Sleep -Seconds 4
    $scan  = (netsh wlan show networks mode=bssid) -join "`n"
    $iface = (netsh wlan show interfaces) -join "`n"
    $body  = @{ scan = $scan; iface = $iface; host = $env:COMPUTERNAME } | ConvertTo-Json
    $r = Invoke-RestMethod -Method Post -Uri $endpoint -ContentType 'application/json; charset=utf-8' `
         -Headers @{ 'X-NetWatch-Token' = $Token } -Body ([System.Text.Encoding]::UTF8.GetBytes($body))
    Write-Host ("{0:HH:mm:ss} envoyé : {1} points d'accès" -f (Get-Date), $r.aps)
  } catch { Write-Warning $_.Exception.Message }
  if (-not $Once) { Start-Sleep -Seconds ($EveryMinutes * 60) }
} while (-not $Once)
