# Synthetic evaluation input only. Never use this voice for the submission video.
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Speech
$fixtureRoot = Join-Path $PSScriptRoot 'multimodal_fixtures'
New-Item -ItemType Directory -Force $fixtureRoot | Out-Null
$speaker = New-Object System.Speech.Synthesis.SpeechSynthesizer
try {
    foreach ($fixture in Get-ChildItem -LiteralPath $fixtureRoot -Filter 'note_*.txt') {
        $speaker.SetOutputToWaveFile([IO.Path]::ChangeExtension($fixture.FullName, '.wav'))
        $speaker.Speak([IO.File]::ReadAllText($fixture.FullName))
        $speaker.SetOutputToNull()
    }
} finally { $speaker.Dispose() }
