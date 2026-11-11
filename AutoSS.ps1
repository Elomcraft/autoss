<#
  AutoSS - automatic Minecraft screenshare scanner.

  Run it on the player's PC during a screenshare. It only READS: nothing is
  installed, changed or saved (unless -Report is used). The only data sent
  anywhere are the SHA-1 hashes and ids of mod jars, to Modrinth's public API
  (disable with -Offline).
  Works without administrator; as administrator it also reads Prefetch, BAM
  and the PCA launch log.

  Usage:
    irm https://raw.githubusercontent.com/Elomcraft/autoss/main/AutoSS.ps1 | iex
  Options:
    & ([scriptblock]::Create((irm https://raw.githubusercontent.com/Elomcraft/autoss/main/AutoSS.ps1))) -Details -Report -Days 7 -Offline

  What it checks:
    1. Running game: Java agents, unsigned DLLs injected into Minecraft,
       cheat/clicker/injector programs running.
    2. Every Minecraft folder (vanilla launcher, Prism, MultiMC/PolyMC,
       Modrinth, CurseForge, GDLauncher, ATLauncher, TLauncher, Lunar,
       Feather, and the folder of the running game): every mod jar (also the
       jars nested inside them) for known cheat clients, cheat modules,
       Java agents and loaders; x-ray resource packs; hacked client versions.
    3. Game logs (latest.log and the archived logs of the last days): cheat
       clients that were loaded, and mods that were loaded but whose jar is
       gone now (deleted before the screenshare).
    4. Downloads, Desktop, Documents, Temp and the Recycle Bin: cheat jars and
       programs, recently deleted jars (they are scanned too).
    5. Execution history: UserAssist, recent files (also files that no longer
       exist), and as administrator Prefetch, BAM and PCA.
    6. Network: cheat websites in the DNS cache, connections to the Doomsday
       server, and the Faker (MITM proxy) bait test.
    7. System: clock changes, cleared event logs, recent reboot or Explorer
       restart, virtual machine, remote-control programs.
#>
[CmdletBinding()]
param(
    # Show every check while it runs.
    [switch]$Details,
    # Also save the full report to the desktop.
    [switch]$Report,
    # How many days back to look in history, logs and recent files.
    [int]$Days = 7,
    # Do not look up mod hashes on Modrinth (no network requests).
    [switch]$Offline
)

# Keep the caller's session clean (this also runs through "irm | iex")
$script:OldEap = $ErrorActionPreference
$script:OldProgress = $ProgressPreference
$ErrorActionPreference = "SilentlyContinue"
$ProgressPreference = "SilentlyContinue"
try { [Console]::OutputEncoding = [System.Text.Encoding]::UTF8 } catch {}
try { Add-Type -AssemblyName System.IO.Compression } catch {}
try { Add-Type -AssemblyName System.IO.Compression.FileSystem } catch {}

$script:Version = "1.0.0"
$script:Lines = New-Object System.Collections.Generic.List[string]
$script:Findings = New-Object System.Collections.Generic.List[object]
$script:Seen = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
$script:Since = (Get-Date).AddDays(-$Days)
$script:IsWin = ($env:OS -eq "Windows_NT")
$script:IsAdmin = $false
try {
    $script:IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
} catch {}
$script:ModJars = New-Object System.Collections.Generic.List[object]
$script:Stats = [ordered]@{ Folders = 0; Jars = 0; Logs = 0; Recycle = 0; History = 0 }

# --------------------------------------------------------------------------
# Signatures
# --------------------------------------------------------------------------
# Package paths inside jars of known cheat clients
$script:ClientSigs = @(
    @{ Name = "Meteor Client"; Level = 3; Pattern = '^meteordevelopment/meteorclient/' },
    @{ Name = "Wurst"; Level = 3; Pattern = '^net/wurstclient/' },
    @{ Name = "LiquidBounce"; Level = 3; Pattern = '^net/ccbluex/liquidbounce/' },
    @{ Name = "Aristois"; Level = 3; Pattern = '^me/deftware/' },
    @{ Name = "RusherHack"; Level = 3; Pattern = '^org/rusherhack/' },
    @{ Name = "Future Client"; Level = 3; Pattern = '^net/futureclient/' },
    @{ Name = "ThunderHack"; Level = 3; Pattern = '^thunder/hack/' },
    @{ Name = "Argon"; Level = 3; Pattern = '^dev/lvstrng/argon/' },
    @{ Name = "Baritone (bot)"; Level = 2; Pattern = '^baritone/' },
    @{ Name = "Advanced XRay"; Level = 2; Pattern = '^pro/mikey/(fabric/)?xray/' },
    @{ Name = "Freecam"; Level = 1; Pattern = '^net/xolt/freecam/' },
    @{ Name = "SeedCracker"; Level = 1; Pattern = '^kaptainwutax/seedcracker' }
)
# Mod ids of known cheats (fabric.mod.json / mods.toml)
$script:CheatIds = @{
    "meteor-client" = @("Meteor Client", 3); "wurst" = @("Wurst", 3); "liquidbounce" = @("LiquidBounce", 3);
    "aristois" = @("Aristois", 3); "rusherhack" = @("RusherHack", 3); "thunderhack" = @("ThunderHack", 3);
    "dd" = @("Doomsday loader", 3); "baritone" = @("Baritone (bot)", 2); "xray" = @("X-Ray mod", 2);
    "advanced-xray" = @("X-Ray mod", 2); "freecam" = @("Freecam", 1); "seedcrackerx" = @("SeedCracker", 1)
}
# Class names typical of cheat modules
$script:StrongModules = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
foreach ($n in @("KillAura", "TriggerBot", "AimAssist", "AimBot", "AutoCrystal", "CrystalAura", "AnchorAura", "AutoAnchor",
        "SelfDestruct", "ClickGui", "AutoClicker", "HitBoxes", "Hitbox", "Reach", "Velocity", "AntiKnockback")) { [void]$script:StrongModules.Add($n) }
$script:WeakModules = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
foreach ($n in @("AutoTotem", "AntiKB", "NoFall", "Scaffold", "XRay", "Freecam", "ESP", "Tracers", "Blink", "Flight", "Fly",
        "NoSlow", "FastPlace", "AutoArmor", "AutoPot", "Criticals", "Surround", "HoleFill", "AutoTrap", "BedAura", "Nuker",
        "Jesus", "Spider", "AutoEat", "ChestStealer", "InvManager", "FakePlayer", "AutoWeb", "Speed", "Timer", "Step")) { [void]$script:WeakModules.Add($n) }
# Program / file names (executables and jars only)
$script:CheatNames = '(?i)(vape|doomsday|meteor[-_ ]?client|wurst|liquidbounce|aristois|rusherhack|thunderhack|future[-_ ]?client|slinky|whiteout|ghost[-_ ]?client|hacked[-_ ]?client|killaura|auto[-_ ]?clicker|faker[-_ .]?\d|^faker)'
$script:ToolNames = '(?i)(clicker|injector|xenos|cheat ?engine|process ?hacker|system ?informer|x64dbg|recaf|bytecode.?viewer|jd-gui|luyten|macro)'
$script:ExecExt = '(?i)\.(exe|jar|dll|bat|cmd|ps1|vbs|msi|zip|rar|7z)$'
# Websites of cheats (DNS cache)
$script:CheatDomains = '(?i)(^|\.)(doomsdayclient\.com|meteorclient\.com|wurstclient\.net|liquidbounce\.net|aristois\.net|vape\.gg|futureclient\.net|rusherhack\.org|impactclient\.net)$'
# DLLs normally loaded into Minecraft from outside Windows/Java
$script:SafeDll = '(?i)(\\lwjgl[^\\]*\\|\\natives?\\|-natives|\\(lwjgl|glfw|openal|OpenAL|jemalloc|jinput|jna|jnidispatch|sqlite|zstd|lz4|snappy|discord|DiscordHook|GameOverlayRenderer|graphics-hook|RTSSHooks|nvspcap|Medal|overwolf|netty|conscrypt|opus|rnnoise|ffmpeg|webp)[^\\]*\.dll$)'

# --------------------------------------------------------------------------
# Output
# --------------------------------------------------------------------------
function Out-Line([string]$Text, [string]$Color = "Gray") {
    if ($Details) { Write-Host $Text -ForegroundColor $Color }
    $script:Lines.Add($Text)
}
function Out-Title([string]$Text) { Out-Line ""; Out-Line ("== " + $Text + " ==") "Cyan" }
function Out-Info([string]$Text) { Out-Line ("  " + $Text) "Gray" }

# Level: 3 = detected, 2 = strong, 1 = hint
function Add-Finding([int]$Level, [string]$Text) {
    if (-not $script:Seen.Add($Text)) { return }
    $script:Findings.Add([pscustomobject]@{ Level = $Level; Text = $Text })
    switch ($Level) {
        3 { Out-Line ("  [DETECTED] " + $Text) "Red" }
        2 { Out-Line ("  [STRONG]   " + $Text) "Magenta" }
        default { Out-Line ("  [HINT]     " + $Text) "Yellow" }
    }
}

function Show-Banner {
    $art = @(
        '    _     _   _  _____   ___      ____   ____',
        '   / \   | | | ||_   _| / _ \    / ___| / ___|',
        '  / _ \  | | | |  | |  | | | |   \___ \ \___ \',
        ' / ___ \ | |_| |  | |  | |_| |    ___) | ___) |',
        '/_/   \_\ \___/   |_|   \___/    |____/ |____/'
    )
    $colors = @("DarkCyan", "Cyan", "Cyan", "Blue", "DarkBlue")
    Write-Host ""
    for ($i = 0; $i -lt $art.Count; $i++) { Write-Host ("  " + $art[$i]) -ForegroundColor $colors[$i] }
    Write-Host ""
    Write-Host ("  " + ("=" * 66)) -ForegroundColor DarkGray
    Write-Host "     Automatic Minecraft screenshare scanner" -NoNewline -ForegroundColor White
    Write-Host ("      v" + $script:Version) -ForegroundColor DarkGray
    Write-Host "     github.com/Elomcraft/autoss" -ForegroundColor DarkGray
    Write-Host ("  " + ("=" * 66)) -ForegroundColor DarkGray
    Write-Host ""
}

$script:StepCount = 7
function Show-Step([int]$Step, [string]$What) {
    if ($Details) { return }
    $width = 24
    $filled = [int][math]::Floor($width * $Step / $script:StepCount)
    $bar = ("#" * $filled) + ("." * ($width - $filled))
    $pct = [int](100 * $Step / $script:StepCount)
    $line = "  Scanning... [" + $bar + "] " + ("{0,3}" -f $pct) + "%  " + $What
    Write-Host ("`r" + $line.PadRight(78)) -NoNewline -ForegroundColor Cyan
}

function Show-Box([string]$Text, [string]$Color) {
    $edge = "  +" + ("-" * ($Text.Length + 6)) + "+"
    Write-Host $edge -ForegroundColor $Color
    Write-Host ("  |   " + $Text + "   |") -ForegroundColor $Color
    Write-Host $edge -ForegroundColor $Color
}

function Format-Date($d) {
    if ($d -eq $null) { return "?" }
    try { return ([datetime]$d).ToString("yyyy-MM-dd HH:mm") } catch { return [string]$d }
}

# --------------------------------------------------------------------------
# Jar scanning
# --------------------------------------------------------------------------
function Read-ZipText($Entry) {
    if ($Entry.Length -gt 2MB) { return "" }
    $sr = $null
    try {
        $sr = New-Object System.IO.StreamReader($Entry.Open())
        return $sr.ReadToEnd()
    } catch { return "" } finally { if ($sr) { $sr.Dispose() } }
}

function Read-ZipInto($Zip, $Info, [int]$Depth) {
    foreach ($e in $Zip.Entries) {
        $n = $e.FullName
        $Info.Entries.Add($n)
        if ($Depth -eq 0) {
            if ($n -match '^(fabric|quilt)\.mod\.json$' -or $n -match '^META-INF/(neoforge\.)?mods\.toml$' -or $n -eq 'mcmod.info') {
                $Info.Meta = $Info.Meta + (Read-ZipText $e) + "`n"
                $Info.HasMeta = $true
            } elseif ($n -eq 'META-INF/MANIFEST.MF') {
                $Info.Manifest = Read-ZipText $e
            }
        }
        if ($Depth -lt 1 -and $n -match '\.jar$' -and $e.Length -lt 40MB) {
            $ms = New-Object System.IO.MemoryStream
            $s = $null; $inner = $null
            try {
                $s = $e.Open()
                $s.CopyTo($ms)
                $ms.Position = 0
                $inner = New-Object System.IO.Compression.ZipArchive($ms, [System.IO.Compression.ZipArchiveMode]::Read)
                $Info.Nested++
                Read-ZipInto $inner $Info ($Depth + 1)
            } catch {} finally {
                if ($inner) { $inner.Dispose() }
                if ($s) { $s.Dispose() }
                $ms.Dispose()
            }
        }
    }
}

function Get-JarInfo([string]$Path) {
    $info = [pscustomobject]@{
        Path = $Path; Entries = (New-Object System.Collections.Generic.List[string]); Meta = ""; HasMeta = $false
        Manifest = ""; Nested = 0; Error = ""
    }
    $fs = $null; $zip = $null
    try {
        $fs = [System.IO.File]::Open($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]'ReadWrite, Delete')
        $zip = New-Object System.IO.Compression.ZipArchive($fs, [System.IO.Compression.ZipArchiveMode]::Read)
        Read-ZipInto $zip $info 0
    } catch {
        $info.Error = $_.Exception.Message
    } finally {
        if ($zip) { $zip.Dispose() }
        if ($fs) { $fs.Dispose() }
    }
    return $info
}

# Returns the mod ids declared in the jar (first = main id)
function Get-ModIds($Info) {
    $ids = @()
    foreach ($m in [regex]::Matches($Info.Meta, '"(?:id|modid)"\s*:\s*"([^"]+)"')) { $ids += $m.Groups[1].Value }
    foreach ($m in [regex]::Matches($Info.Meta, '(?m)^\s*modId\s*=\s*"([^"]+)"')) { $ids += $m.Groups[1].Value }
    return $ids
}

function Test-Jar([string]$Path, [string]$Where) {
    $script:Stats.Jars++
    $info = Get-JarInfo $Path
    if ($info.Error) { Out-Info ("Could not read " + $Path + ": " + $info.Error); return $null }
    $leaf = Split-Path $Path -Leaf
    $joined = [string]::Join("`n", $info.Entries)

    # Known cheat clients by package
    foreach ($sig in $script:ClientSigs) {
        if ([regex]::IsMatch($joined, '(?m)' + $sig.Pattern)) {
            Add-Finding $sig.Level ($sig.Name + " inside " + $Where + ": " + $Path)
        }
    }
    # Known cheat mod ids
    $ids = @(Get-ModIds $info)
    foreach ($id in $ids) {
        $key = $id.ToLower()
        if ($script:CheatIds.ContainsKey($key)) {
            $c = $script:CheatIds[$key]
            Add-Finding $c[1] ($c[0] + " (mod id '" + $id + "') inside " + $Where + ": " + $Path)
        }
    }
    # Java agent in the manifest (can inject into the game)
    if ($info.Manifest -match '(?m)^(Premain-Class|Agent-Class|Launcher-Agent-Class)\s*:\s*(\S+)') {
        $cls = $Matches[2]
        if ($cls -match '^(org\.spongepowered\.tools\.agent|net\.bytebuddy\.agent)') {
            Add-Finding 1 ("Jar with a standard Java agent (" + $cls + ") in " + $Where + ": " + $Path)
        } else {
            Add-Finding 2 ("Java agent / injector jar (" + $cls + ") in " + $Where + ": " + $Path)
        }
    }
    # Cheat module class names
    $strong = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    $weak = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    $classes = 0; $short = 0
    foreach ($m in [regex]::Matches($joined, '(?m)(?:^|/)([A-Za-z0-9_]+)(?:\$[^/\n]*)?\.class$')) {
        $classes++
        $simple = $m.Groups[1].Value
        if ($simple.Length -le 2) { $short++ }
        $base = $simple -replace '(Module|Hack|Feature|Cheat|Mod)$', ''
        if ($base -eq "") { $base = $simple }
        if ($script:StrongModules.Contains($base)) { [void]$strong.Add($base) }
        elseif ($script:WeakModules.Contains($base)) { [void]$weak.Add($base) }
    }
    $mods = @($strong) + @($weak)
    if ($strong.Count -ge 2 -or ($strong.Count -ge 1 -and $weak.Count -ge 2)) {
        Add-Finding 2 ("Cheat modules (" + ($mods -join ", ") + ") inside " + $Where + ": " + $Path)
    } elseif ($strong.Count -eq 1 -or $weak.Count -ge 3) {
        Add-Finding 1 ("Possible cheat modules (" + ($mods -join ", ") + ") inside " + $Where + ": " + $Path)
    }
    # Obfuscated jar
    if ($classes -ge 30 -and ($short / $classes) -gt 0.6) {
        Add-Finding 1 ("Heavily obfuscated jar in " + $Where + ": " + $Path)
    }
    # Loader-like jar: random name, no mod info
    if (-not $info.HasMeta -and $Where -match 'mods folder') {
        if ($leaf -match '^[a-z0-9]{5,10}\.jar$' -and $leaf -notmatch '\d+\.\d+') {
            Add-Finding 2 ("Random-named jar with no mod info in " + $Where + " (typical of injected loaders): " + $Path)
        } else {
            Add-Finding 1 ("Jar with no mod info in " + $Where + ": " + $Path)
        }
    }
    # Name of the file itself
    if ($leaf -match $script:CheatNames) { Add-Finding 2 ("Cheat-like file name in " + $Where + ": " + $Path) }
    # What the mod says about itself
    $about = ""
    foreach ($m in [regex]::Matches($info.Meta, '"(?:name|description)"\s*:\s*"([^"]*)"')) { $about += " " + $m.Groups[1].Value }
    foreach ($m in [regex]::Matches($info.Meta, '(?m)^\s*(?:displayName|description)\s*=\s*[\x22\x27]+([^\x22\x27]*)')) { $about += " " + $m.Groups[1].Value }
    $about = (($ids -join " ") + " " + $about)
    if ($about -match '(?i)(\besp\b|(?<!anti[- ])(?<!anti)x-?ray|wall ?hack|kill ?aura|aim ?bot|aim ?assist|trigger ?bot|auto ?clicker|ghost client|hacked client|(?<!anti[- ])(?<!anti)\bcheats?\b)') {
        Add-Finding 2 ("Mod describes itself as '" + $Matches[1] + "' in " + $Where + ": " + $Path)
    } elseif ($about -match '(?i)(seed ?crack|free ?cam|automation|macro|hit ?box|\breach\b|ore finder|block finder|player finder|\bhacks?\b|\bbypass)') {
        Add-Finding 1 ("Mod describes itself as '" + $Matches[1] + "' in " + $Where + ": " + $Path)
    }
    if ($Where -match 'mods folder') {
        $first = ""; if ($ids.Count -gt 0) { $first = $ids[0] }
        $script:ModJars.Add([pscustomobject]@{ Path = $Path; Leaf = $leaf; Id = $first; Sha1 = "" })
        Out-Info ("  jar: " + $leaf + $(if ($first) { " [" + $first + "]" } else { "" }))
    }
    return $ids
}

# --------------------------------------------------------------------------
# Game logs
# --------------------------------------------------------------------------
function Read-GzText([string]$Path) {
    $fs = $null; $gz = $null; $sr = $null
    try {
        $fs = [System.IO.File]::Open($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]'ReadWrite, Delete')
        $gz = New-Object System.IO.Compression.GZipStream($fs, [System.IO.Compression.CompressionMode]::Decompress)
        $sr = New-Object System.IO.StreamReader($gz)
        return $sr.ReadToEnd()
    } catch { return "" } finally {
        if ($sr) { $sr.Dispose() } elseif ($gz) { $gz.Dispose() }
        if ($fs) { $fs.Dispose() }
    }
}

function Read-SharedText([string]$Path) {
    $fs = $null; $sr = $null
    try {
        $fs = [System.IO.File]::Open($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]'ReadWrite, Delete')
        $sr = New-Object System.IO.StreamReader($fs)
        return $sr.ReadToEnd()
    } catch { return "" } finally { if ($sr) { $sr.Dispose() } elseif ($fs) { $fs.Dispose() } }
}

# Top-level mod ids from a Fabric/Quilt "Loading N mods:" list
function Get-LoggedMods([string]$Text) {
    $ids = New-Object System.Collections.Generic.List[string]
    $m = [regex]::Match($Text, '(?m)Loading \d+ mods:\s*\r?\n((?:[ \t]+[^\r\n]*\r?\n)+)')
    if ($m.Success) {
        foreach ($l in ($m.Groups[1].Value -split "`n")) {
            if ($l -match '^\s+-\s+([^\s]+)\s') { $ids.Add($Matches[1]) }
        }
    }
    return $ids
}

function Test-Logs([string]$Inst, $JarIds) {
    $logDir = Join-Path $Inst "logs"
    if (-not (Test-Path -LiteralPath $logDir)) { return }
    $files = @(Get-ChildItem -LiteralPath $logDir -File -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -match '\.log(\.gz)?$' -and $_.LastWriteTime -gt $script:Since } |
        Sort-Object LastWriteTime -Descending | Select-Object -First 25)
    foreach ($f in $files) {
        $script:Stats.Logs++
        if ($f.Name -like "*.gz") { $text = Read-GzText $f.FullName } else { $text = Read-SharedText $f.FullName }
        if (-not $text) { continue }
        $logged = Get-LoggedMods $text
        foreach ($id in $logged) {
            $key = $id.ToLower()
            if ($script:CheatIds.ContainsKey($key)) {
                $c = $script:CheatIds[$key]
                Add-Finding $c[1] ($c[0] + " was loaded in a game on " + (Format-Date $f.LastWriteTime) + " (" + $f.FullName + ")")
            }
        }
        foreach ($sig in @("meteorclient", "wurstclient", "liquidbounce", "rusherhack", "thunderhack", "doomsday")) {
            if ($text -match ('(?i)' + $sig)) { Add-Finding 2 ("'" + $sig + "' appears in the game log " + $f.FullName) }
        }
        # Mods loaded in the last game whose jar is gone now
        if ($f.Name -eq "latest.log" -and $logged.Count -gt 0 -and $JarIds -ne $null) {
            $head = $text.Substring(0, [math]::Min($text.Length, 20000))
            if ($head -match '(?i)(feather|lunar|badlion)') { continue }
            $builtin = '^(minecraft|java|fabricloader|quilt_loader|mixinextras|fabric-api|quilted_fabric_api)$'
            $gone = @($logged | Where-Object { $_ -notmatch $builtin -and -not $JarIds.Contains($_) })
            if ($gone.Count -gt 0 -and $gone.Count -le 15) {
                Add-Finding 2 ("Mods loaded in the last game (" + (Format-Date $f.LastWriteTime) + ") but no longer in the mods folder: " + ($gone -join ", ") + " (" + $Inst + ")")
            }
        }
    }
}

# --------------------------------------------------------------------------
# Start
# --------------------------------------------------------------------------
Show-Banner
Out-Line ("AutoSS " + $script:Version + " - " + (Get-Date -Format "yyyy-MM-dd HH:mm:ss")) "White"
Out-Line ("Computer: " + $env:COMPUTERNAME + "   User: " + $env:USERNAME + "   Admin: " + $script:IsAdmin + "   History: last " + $Days + " days") "White"
if (-not $script:IsWin) {
    Write-Host "  AutoSS only works on Windows." -ForegroundColor Yellow
    $ErrorActionPreference = $script:OldEap; $ProgressPreference = $script:OldProgress
    return
}

# --------------------------------------------------------------------------
# 1. Running game and programs
# --------------------------------------------------------------------------
Show-Step 0 "running programs"
Out-Title "1. Running game and programs"
$procs = @(Get-Process -ErrorAction SilentlyContinue)
$cim = @(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue)
$javaProcs = @($procs | Where-Object { $_.ProcessName -match '^javaw?$' })
$gameDirs = New-Object System.Collections.Generic.List[string]
$gameStart = $null
foreach ($jp in $javaProcs) {
    $c = $cim | Where-Object { $_.ProcessId -eq $jp.Id } | Select-Object -First 1
    $cmd = ""
    if ($c) { $cmd = [string]$c.CommandLine }
    if ($cmd -notmatch '(?i)(net\.minecraft|fabric|forge|quilt|minecraft|lunar|feather|badlion|--gameDir)') { continue }
    Out-Info ("Minecraft: " + $jp.ProcessName + " PID " + $jp.Id + " started " + (Format-Date $jp.StartTime))
    if ($gameStart -eq $null -or $jp.StartTime -lt $gameStart) { $gameStart = $jp.StartTime }
    if ($cmd -match '--gameDir\s+(?:"([^"]+)"|(\S+))') {
        $gd = $Matches[1]; if (-not $gd) { $gd = $Matches[2] }
        $gameDirs.Add($gd)
        Out-Info ("Game folder: " + $gd)
    }
    foreach ($m in [regex]::Matches($cmd, '-javaagent:(?:"([^"]+)"|([^\s]+))')) {
        $agent = $m.Groups[1].Value; if (-not $agent) { $agent = $m.Groups[2].Value }
        $agentJar = ($agent -split '=')[0]
        if ($agentJar -match '(?i)\\(\.lunarclient|\.feather|\.minecraft|Badlion Client|PrismLauncher|ModrinthApp|com\.modrinth\.theseus|curseforge)\\') {
            Out-Info ("Launcher Java agent: " + $agentJar)
        } else {
            Add-Finding 2 ("Java agent loaded into Minecraft: " + $agentJar)
        }
        if (Test-Path -LiteralPath $agentJar) { [void](Test-Jar $agentJar "a Java agent") }
    }
    if ($cmd -match '(?i)-Dfabric\.addMods=(?:"([^"]+)"|(\S+))') {
        $am = $Matches[1]; if (-not $am) { $am = $Matches[2] }
        Add-Finding 1 ("Minecraft loads extra mods from outside the mods folder: " + $am)
    }
    # DLLs injected into the game
    $jhome = $null
    try { $jhome = Split-Path (Split-Path $jp.Path) } catch {}
    $loaded = @()
    try { $loaded = @($jp.Modules) } catch { Out-Info ("Cannot list the DLLs of PID " + $jp.Id + " (run 64-bit PowerShell).") }
    foreach ($mod in $loaded) {
        $f = [string]$mod.FileName
        if (-not $f) { continue }
        if ($f.StartsWith($env:WINDIR, [StringComparison]::OrdinalIgnoreCase)) { continue }
        if ($jhome -and $f.StartsWith($jhome, [StringComparison]::OrdinalIgnoreCase)) { continue }
        if ($f -match $script:SafeDll) { continue }
        $sig = Get-AuthenticodeSignature -LiteralPath $f -ErrorAction SilentlyContinue
        if ($sig -and $sig.Status -eq "Valid") { continue }
        if ($f -match '(?i)\\(Temp|Downloads|Desktop)\\') {
            Add-Finding 2 ("Unsigned DLL injected into Minecraft (PID " + $jp.Id + "): " + $f)
        } else {
            Add-Finding 1 ("Unsigned DLL loaded into Minecraft (PID " + $jp.Id + "): " + $f)
        }
    }
}
if ($javaProcs.Count -eq 0) { Out-Info "Minecraft is not running." }
# Java options that inject agents into every Java program
foreach ($scope in @("User", "Machine", "Process")) {
    foreach ($var in @("JAVA_TOOL_OPTIONS", "_JAVA_OPTIONS", "JDK_JAVA_OPTIONS")) {
        $v = [Environment]::GetEnvironmentVariable($var, $scope)
        if ($v -and $v -match '(?i)javaagent|agentpath|agentlib') { Add-Finding 2 ($var + " (" + $scope + ") injects into every Java program: " + $v) }
    }
}
# Cheat, clicker, injector and remote-control programs
$browsers = '(?i)^(chrome|msedge|firefox|opera|brave|vivaldi|discord|spotify|explorer|steamwebhelper|code|notepad\+\+|powershell|pwsh|windowsterminal|conhost|cmd)$'
foreach ($p in $procs) {
    $title = ""
    if ($p.ProcessName -notmatch $browsers) { try { $title = [string]$p.MainWindowTitle } catch {} }
    $path = ""; try { $path = [string]$p.Path } catch {}
    $label = $p.ProcessName + ".exe" + $(if ($title) { " (window '" + $title + "')" } else { "" }) + $(if ($path) { " " + $path } else { "" })
    if (($p.ProcessName + ".exe") -match $script:CheatNames -or $title -match $script:CheatNames) {
        Add-Finding 2 ("Cheat-like program running: " + $label)
    } elseif (($p.ProcessName + ".exe") -match $script:ToolNames -or ($title -match $script:ToolNames -and $title -notmatch '(?i)minecraft')) {
        Add-Finding 1 ("Clicker/injector/debugging tool running: " + $label)
    }
    if ($p.ProcessName -match '(?i)^(anydesk|teamviewer|rustdesk|parsecd|rutserv|ammyy)') {
        Add-Finding 1 ("Remote-control program running: " + $p.ProcessName)
    }
}

# --------------------------------------------------------------------------
# 2. Minecraft folders, mods, packs, versions
# --------------------------------------------------------------------------
Show-Step 1 "Minecraft folders and mods"
Out-Title "2. Minecraft folders"
$instRoots = New-Object System.Collections.Generic.List[string]
$instSeen = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
function Add-Inst([string]$p) {
    if (-not $p) { return }
    $p = $p.TrimEnd('\')
    if ((Test-Path -LiteralPath $p) -and $instSeen.Add($p)) { $instRoots.Add($p) }
}
foreach ($g in $gameDirs) { Add-Inst $g }
$searchRoots = @(
    (Join-Path $env:APPDATA ".minecraft"),
    (Join-Path $env:APPDATA "PrismLauncher\instances"),
    (Join-Path $env:APPDATA "PolyMC\instances"),
    (Join-Path $env:APPDATA "com.modrinth.theseus\profiles"),
    (Join-Path $env:APPDATA "ModrinthApp\profiles"),
    (Join-Path $env:USERPROFILE "curseforge\minecraft\Instances"),
    (Join-Path $env:APPDATA "gdlauncher_next\instances"),
    (Join-Path $env:APPDATA "ATLauncher\instances"),
    (Join-Path $env:APPDATA ".tlauncher"),
    (Join-Path $env:APPDATA ".feather"),
    (Join-Path $env:USERPROFILE ".lunarclient"),
    (Join-Path $env:USERPROFILE "Desktop"),
    (Join-Path $env:USERPROFILE "Downloads")
)
foreach ($r in $searchRoots) {
    if (-not (Test-Path -LiteralPath $r)) { continue }
    if (Test-Path -LiteralPath (Join-Path $r "mods")) { Add-Inst $r }
    Get-ChildItem -LiteralPath $r -Directory -Recurse -Depth 4 -Filter "mods" -ErrorAction SilentlyContinue |
        Where-Object { $_.FullName -notmatch '(?i)\\(jre|runtime|cache|assets|libraries|node_modules|\.git)\\' } |
        ForEach-Object { Add-Inst $_.Parent.FullName }
}
$xrayPack = '(?i)x[-_ ]?ray'
foreach ($inst in $instRoots) {
    $script:Stats.Folders++
    Out-Info ("Folder: " + $inst)
    $modsDir = Join-Path $inst "mods"
    $jarIds = $null
    if (Test-Path -LiteralPath $modsDir) {
        $jarIds = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
        $jars = @(Get-ChildItem -LiteralPath $modsDir -File -Recurse -Depth 1 -ErrorAction SilentlyContinue | Where-Object { $_.Name -match '\.(jar|disabled|zip)$' })
        foreach ($j in $jars) {
            $ids = Test-Jar $j.FullName ("the mods folder " + $modsDir)
            if ($ids) { foreach ($i in @($ids)[0..0]) { [void]$jarIds.Add($i) } }
        }
        $md = Get-Item -LiteralPath $modsDir
        if ($gameStart -ne $null -and $md.LastWriteTime -gt $gameStart) {
            $lvl = 1
            foreach ($g in $gameDirs) { if ($inst.StartsWith($g.TrimEnd('\'), [StringComparison]::OrdinalIgnoreCase)) { $lvl = 2 } }
            Add-Finding $lvl ("Mods folder changed while the game was running (" + (Format-Date $md.LastWriteTime) + "): " + $modsDir)
        }
    }
    Test-Logs $inst $jarIds
    foreach ($sub in @("resourcepacks", "texturepacks", "shaderpacks")) {
        $rp = Join-Path $inst $sub
        if (Test-Path -LiteralPath $rp) {
            Get-ChildItem -LiteralPath $rp -ErrorAction SilentlyContinue | Where-Object { $_.Name -match $xrayPack } |
                ForEach-Object { Add-Finding 2 ("X-ray pack: " + $_.FullName) }
        }
    }
    $ver = Join-Path $inst "versions"
    if (Test-Path -LiteralPath $ver) {
        Get-ChildItem -LiteralPath $ver -Directory -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -match '(?i)(wurst|meteor|liquidbounce|aristois|impact|rusherhack|thunderhack|doomsday|vape|inertia|sigma|novoline|tenacity|exhibition)' } |
            ForEach-Object { Add-Finding 2 ("Hacked client version installed: " + $_.FullName) }
    }
}
if ($instRoots.Count -eq 0) { Out-Info "No Minecraft folders found." }

# Mods that are not published on Modrinth, or differ from every published file
# (private mods, CurseForge-only mods, or modified copies of known mods).
# Only the SHA-1 hashes and mod ids are sent to Modrinth's public API.
if (-not $Offline -and $script:ModJars.Count -gt 0) {
    try {
        try { [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12 } catch {}
        $ua = "Elomcraft/autoss/" + $script:Version + " (github.com/Elomcraft/autoss)"
        $byHash = @{}
        foreach ($mj in $script:ModJars) {
            if ($mj.Leaf -notmatch '\.jar$') { continue }
            $fh = Get-FileHash -LiteralPath $mj.Path -Algorithm SHA1 -ErrorAction SilentlyContinue
            if ($fh) { $mj.Sha1 = $fh.Hash.ToLower(); $byHash[$mj.Sha1] = $mj }
        }
        if ($byHash.Count -gt 0) {
            $body = '{"hashes":["' + (@($byHash.Keys) -join '","') + '"],"algorithm":"sha1"}'
            $known = Invoke-RestMethod -Uri "https://api.modrinth.com/v2/version_files" -Method Post -Body $body -ContentType "application/json" -UserAgent $ua -TimeoutSec 20
            $knownNames = @()
            if ($known) { $knownNames = @($known.PSObject.Properties | ForEach-Object { $_.Name }) }
            $unknown = @($byHash.Keys | Where-Object { $knownNames -notcontains $_ } | ForEach-Object { $byHash[$_] })
            Out-Info ("Modrinth: " + ($byHash.Count - $unknown.Count) + " of " + $byHash.Count + " mod files are published there.")
            $idList = @($unknown | Where-Object { $_.Id -match '^[A-Za-z0-9_.\-]+$' } | ForEach-Object { $_.Id.ToLower() } | Select-Object -Unique)
            $projects = @{}
            if ($idList.Count -gt 0) {
                $q = "https://api.modrinth.com/v2/projects?ids=" + [uri]::EscapeDataString('["' + ($idList -join '","') + '"]')
                foreach ($pr in @(Invoke-RestMethod -Uri $q -UserAgent $ua -TimeoutSec 20)) { if ($pr.slug) { $projects[([string]$pr.slug).ToLower()] = [string]$pr.title } }
            }
            $modified = @(); $private = @()
            foreach ($u in $unknown) {
                if ($u.Id -and $projects.ContainsKey($u.Id.ToLower())) { $modified += ($u.Leaf + " (" + $projects[$u.Id.ToLower()] + ")") }
                else { $private += $u.Leaf }
            }
            if ($modified.Count -gt 0) {
                Add-Finding 1 ("Mods that differ from every file published on Modrinth (modified, or downloaded elsewhere): " + (($modified | Select-Object -First 25) -join ", "))
            }
            if ($private.Count -gt 0) {
                Add-Finding 1 ("Mods not published on Modrinth (private, custom or CurseForge-only - check them): " + (($private | Select-Object -First 25) -join ", "))
            }
        }
    } catch {
        Out-Info ("Modrinth lookup failed: " + $_.Exception.Message)
    }
}

# --------------------------------------------------------------------------
# 3. Downloads, Desktop, Documents, Temp
# --------------------------------------------------------------------------
Show-Step 2 "downloads and temp"
Out-Title "3. Downloads, Desktop, Documents, Temp"
$places = @((Join-Path $env:USERPROFILE "Downloads"), (Join-Path $env:USERPROFILE "Desktop"), (Join-Path $env:USERPROFILE "Documents"), $env:TEMP)
foreach ($pl in $places) {
    if (-not $pl -or -not (Test-Path -LiteralPath $pl)) { continue }
    $files = @(Get-ChildItem -LiteralPath $pl -File -Recurse -Depth 2 -Force -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -match $script:ExecExt -and $_.LastWriteTime -gt $script:Since -and $_.FullName -notmatch '(?i)\\mods\\' } |
        Select-Object -First 400)
    foreach ($f in $files) {
        if ($f.Extension -eq ".jar" -and $f.Length -lt 60MB) { [void](Test-Jar $f.FullName ("downloads/temp")) }
        elseif ($f.Name -match $script:CheatNames) { Add-Finding 2 ("Cheat-like file (" + (Format-Date $f.LastWriteTime) + "): " + $f.FullName) }
        elseif ($f.Name -match $script:ToolNames) { Add-Finding 1 ("Clicker/injector-like file (" + (Format-Date $f.LastWriteTime) + "): " + $f.FullName) }
    }
}

# --------------------------------------------------------------------------
# 4. Recycle Bin
# --------------------------------------------------------------------------
Show-Step 3 "recycle bin"
Out-Title "4. Recycle Bin"
try {
    $shellApp = New-Object -ComObject Shell.Application
    $bin = $shellApp.NameSpace(10)
    foreach ($it in @($bin.Items())) {
        $script:Stats.Recycle++
        $deleted = $null
        try { $deleted = $it.ExtendedProperty("System.Recycle.DateDeleted") } catch {}
        $orig = ""
        try { $orig = [string]$bin.GetDetailsOf($it, 1) } catch {}
        $name = [string]$it.Name
        $path = [string]$it.Path
        $ext = [System.IO.Path]::GetExtension($path)
        $recent = ($deleted -eq $null -or ([datetime]$deleted) -gt $script:Since)
        if (-not $recent) { continue }
        $label = $name + " (from " + $orig + ", deleted " + (Format-Date $deleted) + ")"
        if ($ext -eq ".jar") {
            Add-Finding 1 ("Jar deleted recently: " + $label)
            if (Test-Path -LiteralPath $path) { [void](Test-Jar $path ("the Recycle Bin (" + $name + ")")) }
        } elseif (($name + $ext) -match $script:CheatNames) {
            Add-Finding 2 ("Cheat-like file deleted recently: " + $label)
        } elseif ($ext -match $script:ExecExt -and ($name + $ext) -match $script:ToolNames) {
            Add-Finding 1 ("Clicker/injector-like file deleted recently: " + $label)
        }
    }
} catch { Out-Info ("Recycle Bin not readable: " + $_.Exception.Message) }

# --------------------------------------------------------------------------
# 5. Execution history
# --------------------------------------------------------------------------
Show-Step 4 "execution history"
Out-Title "5. Execution history"
function ConvertFrom-Rot13([string]$s) {
    $sb = New-Object System.Text.StringBuilder
    foreach ($ch in $s.ToCharArray()) {
        $c = [int]$ch
        if ($c -ge 65 -and $c -le 90) { $c = (($c - 65 + 13) % 26) + 65 }
        elseif ($c -ge 97 -and $c -le 122) { $c = (($c - 97 + 13) % 26) + 97 }
        [void]$sb.Append([char]$c)
    }
    return $sb.ToString()
}
function Test-Executed([string]$What, [string]$Source, $When) {
    $script:Stats.History++
    if ($When -ne $null -and ([datetime]$When) -lt $script:Since) { return }
    $leaf = Split-Path $What -Leaf
    if ($leaf -match $script:CheatNames) {
        Add-Finding 2 ("Cheat-like program run (" + $Source + ", " + (Format-Date $When) + "): " + $What)
    } elseif ($leaf -match $script:ToolNames) {
        Add-Finding 1 ("Clicker/injector-like program run (" + $Source + ", " + (Format-Date $When) + "): " + $What)
    }
}
# UserAssist (programs opened from Explorer)
try {
    $ua = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist"
    foreach ($g in @(Get-ChildItem $ua -ErrorAction SilentlyContinue)) {
        $k = Get-Item (Join-Path $g.PSPath "Count") -ErrorAction SilentlyContinue
        if (-not $k) { continue }
        foreach ($vn in $k.GetValueNames()) {
            $data = $k.GetValue($vn)
            $last = $null
            if ($data -is [byte[]] -and $data.Length -ge 68) {
                $ft = [BitConverter]::ToInt64($data, 60)
                if ($ft -gt 0) { try { $last = [DateTime]::FromFileTime($ft) } catch {} }
            }
            if ($last -ne $null) { Test-Executed (ConvertFrom-Rot13 $vn) "UserAssist" $last }
        }
    }
} catch {}
# Recent files (also ones that no longer exist)
try {
    $ws = New-Object -ComObject WScript.Shell
    $recentDir = Join-Path $env:APPDATA "Microsoft\Windows\Recent"
    foreach ($l in @(Get-ChildItem -LiteralPath $recentDir -Filter *.lnk -ErrorAction SilentlyContinue | Where-Object { $_.LastWriteTime -gt $script:Since })) {
        $t = ""
        try { $t = [string]$ws.CreateShortcut($l.FullName).TargetPath } catch {}
        if (-not $t) { continue }
        Test-Executed $t "recent files" $l.LastWriteTime
        if ($t -match '(?i)\.(jar|exe|dll)$' -and -not (Test-Path -LiteralPath $t)) {
            $lvl = 1
            if ((Split-Path $t -Leaf) -match $script:CheatNames) { $lvl = 2 }
            Add-Finding $lvl ("Recently opened file no longer exists (" + (Format-Date $l.LastWriteTime) + "): " + $t)
        }
    }
} catch {}
if ($script:IsAdmin) {
    # Prefetch
    foreach ($pf in @(Get-ChildItem (Join-Path $env:WINDIR "Prefetch") -Filter *.pf -ErrorAction SilentlyContinue)) {
        $exe = ($pf.Name -replace '-[0-9A-F]{8}\.pf$', '')
        Test-Executed $exe "Prefetch" $pf.LastWriteTime
    }
    # BAM
    foreach ($bamRoot in @("HKLM:\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings", "HKLM:\SYSTEM\CurrentControlSet\Services\bam\UserSettings")) {
        foreach ($sidKey in @(Get-ChildItem $bamRoot -ErrorAction SilentlyContinue)) {
            $k = Get-Item $sidKey.PSPath -ErrorAction SilentlyContinue
            if (-not $k) { continue }
            foreach ($vn in $k.GetValueNames()) {
                $d = $k.GetValue($vn)
                $last = $null
                if ($d -is [byte[]] -and $d.Length -ge 8) { try { $last = [DateTime]::FromFileTime([BitConverter]::ToInt64($d, 0)) } catch {} }
                Test-Executed $vn "BAM" $last
            }
        }
    }
    # PCA launch log (Windows 11)
    $pca = Join-Path $env:WINDIR "appcompat\pca\PcaAppLaunchDic.txt"
    if (Test-Path -LiteralPath $pca) {
        foreach ($line in @(Get-Content -LiteralPath $pca -ErrorAction SilentlyContinue)) {
            $parts = $line -split '\|'
            if ($parts.Count -ge 2) {
                $when = $null; try { $when = [datetime]$parts[1] } catch {}
                Test-Executed $parts[0] "PCA" $when
            }
        }
    }
} else {
    Out-Info "Not administrator: Prefetch, BAM and PCA skipped."
}

# --------------------------------------------------------------------------
# 6. Network
# --------------------------------------------------------------------------
Show-Step 5 "network"
Out-Title "6. Network"
try {
    foreach ($d in @(Get-DnsClientCache -ErrorAction SilentlyContinue)) {
        $n = [string]$d.Entry
        if ($n -match $script:CheatDomains) { Add-Finding 2 ("Cheat website visited recently (DNS cache): " + $n) }
    }
} catch {}
try {
    $dd = @(Get-NetTCPConnection -RemoteAddress "165.22.196.0" -ErrorAction SilentlyContinue)
    if ($dd.Count -gt 0) { Add-Finding 2 "Connected to 165.22.196.0, the server Doomsday downloads its cheat from." }
} catch {}
# Faker bait: connections to non-existent IPs on Minecraft ports must never succeed
function Test-Connect([string]$Ip, [int]$Port) {
    $cl = New-Object System.Net.Sockets.TcpClient
    try {
        $t = $cl.ConnectAsync($Ip, $Port)
        $ok = $false
        try { $ok = $t.Wait(1500) } catch { $ok = $false }
        return ($ok -and $t.Status -eq "RanToCompletion" -and $cl.Connected)
    } catch { return $false } finally { try { $cl.Close() } catch {} }
}
$baitPorts = New-Object System.Collections.Generic.List[int]
$baitPorts.Add(25565)
try {
    $ids = @($javaProcs | ForEach-Object { $_.Id })
    foreach ($c in @(Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue | Where-Object { $ids -contains $_.OwningProcess })) {
        if ($c.RemotePort -ne 443 -and $c.RemotePort -ne 80 -and [string]$c.RemoteAddress -notmatch '^(127\.|::1)' -and -not $baitPorts.Contains([int]$c.RemotePort)) { $baitPorts.Add([int]$c.RemotePort) }
    }
} catch {}
$baits = @("192.0.2.1", "198.51.100.1", "203.0.113.1")
$controlHit = $false
foreach ($b in $baits) { if (Test-Connect $b 47321) { $controlHit = $true } }
if ($controlHit) {
    Out-Info "This network intercepts every port; Faker bait test skipped."
} else {
    foreach ($port in $baitPorts) {
        $hit = @($baits | Where-Object { Test-Connect $_ $port })
        if ($hit.Count -gt 0) {
            Add-Finding 3 ("Faker (MITM proxy): connections to non-existent IPs on port " + $port + " succeed. The game connection goes through another PC.")
        } else {
            Out-Info ("Faker bait on port " + $port + ": clean")
        }
    }
}

# --------------------------------------------------------------------------
# 7. System
# --------------------------------------------------------------------------
Show-Step 6 "system"
Out-Title "7. System"
try {
    $os = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue
    $boot = $os.LastBootUpTime
    Out-Info ("Last boot: " + (Format-Date $boot))
    if ($boot -and $boot -gt (Get-Date).AddMinutes(-30)) {
        Add-Finding 1 ("The PC was restarted shortly before the scan (" + (Format-Date $boot) + "); some traces are lost on reboot.")
    }
    $explorer = @($procs | Where-Object { $_.ProcessName -eq "explorer" } | Sort-Object StartTime | Select-Object -First 1)
    if ($explorer.Count -gt 0 -and $boot -and $explorer[0].StartTime -gt $boot.AddMinutes(10)) {
        Add-Finding 1 ("Explorer was restarted at " + (Format-Date $explorer[0].StartTime) + " (long after boot).")
    }
} catch {}
try {
    foreach ($e in @(Get-WinEvent -FilterHashtable @{ LogName = "System"; Id = 104; StartTime = $script:Since } -ErrorAction SilentlyContinue)) {
        Add-Finding 2 ("An event log was cleared at " + (Format-Date $e.TimeCreated) + ".")
    }
} catch {}
try {
    foreach ($e in @(Get-WinEvent -FilterHashtable @{ LogName = "System"; ProviderName = "Microsoft-Windows-Kernel-General"; Id = 1; StartTime = $script:Since } -ErrorAction SilentlyContinue)) {
        try {
            $new = [datetime]$e.Properties[0].Value
            $old = [datetime]$e.Properties[1].Value
            if ([math]::Abs(($new - $old).TotalMinutes) -gt 5) {
                Add-Finding 2 ("The system clock was changed from " + (Format-Date $old) + " to " + (Format-Date $new) + " (used to fake file dates).")
            }
        } catch {}
    }
} catch {}
try {
    $cs = Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue
    if (($cs.Manufacturer + " " + $cs.Model) -match '(?i)(vmware|virtualbox|qemu|kvm|xen|parallels|virtual machine|hyper-v)') {
        Add-Finding 1 ("This is a virtual machine (" + $cs.Manufacturer + " " + $cs.Model + ").")
    }
} catch {}

# --------------------------------------------------------------------------
# Verdict
# --------------------------------------------------------------------------
Show-Step 7 "done"
Write-Host ""
Write-Host ""
$max = 0
foreach ($h in $script:Findings) { if ($h.Level -gt $max) { $max = $h.Level } }
$strongCount = @($script:Findings | Where-Object { $_.Level -eq 2 }).Count
$hintCount = @($script:Findings | Where-Object { $_.Level -eq 1 }).Count
if ($max -ge 3) { $verdict = "CHEATS DETECTED"; $color = "Red" }
elseif ($strongCount -ge 1) { $verdict = "SUSPICIOUS - review the findings"; $color = "Magenta" }
elseif ($hintCount -ge 1) { $verdict = "CLEAN - only minor hints"; $color = "Yellow" }
else { $verdict = "CLEAN - nothing found"; $color = "Green" }
$script:Lines.Add(""); $script:Lines.Add("== Verdict =="); $script:Lines.Add($verdict)
Show-Box $verdict $color
$labels = @{ 3 = "DETECTED"; 2 = "STRONG  "; 1 = "HINT    " }
$colorsByLevel = @{ 3 = "Red"; 2 = "Magenta"; 1 = "Yellow" }
if (-not $Details) {
    foreach ($h in ($script:Findings | Sort-Object Level -Descending)) {
        Write-Host ("   [" + $labels[$h.Level] + "] ") -NoNewline -ForegroundColor $colorsByLevel[$h.Level]
        Write-Host $h.Text -ForegroundColor Gray
    }
}
$summary = "   Scanned: " + $script:Stats.Folders + " Minecraft folders, " + $script:Stats.Jars + " jars, " + $script:Stats.Logs + " game logs, " +
    $script:Stats.Recycle + " recycle bin items, " + $script:Stats.History + " history entries."
Write-Host ""
Write-Host $summary -ForegroundColor DarkGray
$script:Lines.Add($summary)
if (-not $script:IsAdmin) {
    Write-Host "   Tip: run PowerShell as administrator to also check Prefetch, BAM and PCA." -ForegroundColor DarkGray
}
if ($Report) {
    try {
        $desk = [Environment]::GetFolderPath("Desktop")
        $path = Join-Path $desk ("AutoSS_" + (Get-Date -Format "yyyyMMdd_HHmmss") + ".txt")
        $script:Lines | Set-Content -Path $path -Encoding UTF8
        Write-Host ("   Report saved to " + $path) -ForegroundColor White
    } catch {}
}
Write-Host ""

$ErrorActionPreference = $script:OldEap
$ProgressPreference = $script:OldProgress
