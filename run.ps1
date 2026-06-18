# Sigma-Forge weekly runner.
# Backtests rules -> writes RULEPACK to repo + vault -> commits -> speaks summary.
# Scheduled task: IGRIS-SigmaForge (weekly). Also runnable by hand.
#
# Data source: defaults to the Ironside honeypot sample. To use fresh telemetry,
# pass -Logs to a newer Cowrie ndjson (v2: pull nightly from pi5security).

param(
  [string]$Logs = "",                 # explicit log file overrides auto source-selection
  [string]$Sensor = "pi5security",
  [int]$MinLiveEvents = 40            # below this, fall back to the curated sample
)
$ErrorActionPreference = 'Continue'
$env:Path = [Environment]::GetEnvironmentVariable('Path','Machine') + ';' +
            [Environment]::GetEnvironmentVariable('Path','User')

$repo   = "$HOME\projects\sigma-forge"
$sample = "$HOME\projects\ironside-soc-lab\data\cowrie_sample.json"
$live   = "$repo\data\cowrie_live.json"
$vault  = 'G:\My Drive\Claude\FractalScholar\Areas\Sigma-Forge'
$logDir = "$HOME\Scripts\briefings"
foreach($d in @($vault,$logDir)){ if(-not(Test-Path $d)){ New-Item -ItemType Directory -Path $d -Force | Out-Null } }
$log = Join-Path $logDir 'sigma-forge.log'
"[{0}] sigma-forge run start" -f (Get-Date -Format 's') | Add-Content $log

# 0. Choose data source: explicit -Logs > live pull (if rich enough) > curated sample
if ($Logs) {
    $source = $Logs; $srcLabel = "explicit"
} else {
    $wslScript = "/mnt/c/Users/$env:USERNAME/projects/sigma-forge/tools/pull_cowrie.sh"
    $pull = wsl -d Ubuntu -- bash $wslScript $Sensor 2>&1
    $pull | Add-Content $log
    $liveCount = if (Test-Path $live) { (Get-Content $live | Where-Object { $_.Trim() }).Count } else { 0 }
    if ($liveCount -ge $MinLiveEvents) {
        $source = $live; $srcLabel = "live:$Sensor ($liveCount events)"
    } else {
        $source = $sample; $srcLabel = "sample (live had only $liveCount events, < $MinLiveEvents)"
    }
}
"[{0}] data source = $srcLabel" -f (Get-Date -Format 's') | Add-Content $log

# 1. Backtest
$res = & python "$repo\sigma_forge.py" --logs $source --rules "$repo\rules" --out "$repo\out" 2>> $log
$res | Add-Content $log
$summary = ($res | Where-Object { $_ -match 'SIGMA_FORGE_OK' }) -replace 'SIGMA_FORGE_OK\s*',''

# 2. Copy the rule pack into the Obsidian vault (dated + latest)
$stamp = Get-Date -Format 'yyyy-MM-dd'
if(Test-Path "$repo\out\RULEPACK.md"){
  Copy-Item "$repo\out\RULEPACK.md" (Join-Path $vault "RulePack-$stamp.md") -Force
  Copy-Item "$repo\out\RULEPACK.md" (Join-Path $vault "RulePack-latest.md") -Force
}

# 3. Commit the refreshed pack so the GitHub portfolio repo stays current.
#    Committer identity comes from the repo-local git config (set once, not in source),
#    so no personal email is embedded in this script.
Push-Location $repo
& git add -A 2>> $log
& git commit -m "Weekly rule pack $stamp -- $summary" 2>> $log | Out-Null
Pop-Location

# 4. Speak a one-line summary
$healthy = ([regex]::Match($summary,'healthy=(\d+)')).Groups[1].Value
$rules   = ([regex]::Match($summary,'rules=(\d+)')).Groups[1].Value
$speak = "Sigma Forge backtested $rules detection rules against your honeypot data. $healthy are healthy and shippable. The rule pack is updated in your vault and repo."
$ttsPanel = Join-Path $HOME '.claude\tts\tts.ps1'
if(Test-Path $ttsPanel){ & pwsh -NoProfile -File $ttsPanel test $speak 2>> $log; "[{0}] spoke" -f (Get-Date -Format 's') | Add-Content $log }

Write-Output $summary
