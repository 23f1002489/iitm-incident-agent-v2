$base = "https://iitm-incident-agent-v2.onrender.com"
$runIds = @(
    "run_2pr4Dw2bB2Qq6N7NMhAxuk",
    "run_8ZwsQ9EuycvdTbqWek7gfj",
    "run_Kzm2ZpwtAZxMEsktBBcpWF",
    "run_5PctkcactCDamXeYGxxRyM",
    "run_uYiU86aH9n7sg2KoVJbvm8",
    "run_s5hUAadNvpCPCMPGvyo2xe",
    "run_esGJ5TMzuku2tVwpEVL6Ga"
)

foreach ($id in $runIds) {
    $r = Invoke-RestMethod -Uri "$base/v2/incidents/$id"
    [PSCustomObject]@{
        RunId       = $id
        Status      = $r.status
        RootCause   = $r.diagnosis.rootCause
        Evidence    = ($r.diagnosis.evidence -join ", ")
        Tools       = ($r.dispatches | ForEach-Object { $_.toolName }) -join ", "
    }
} | Format-List
