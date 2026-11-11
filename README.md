# AutoSS

Automatic Minecraft screenshare scanner. One command, read-only, no install.

## Usage

On the player's PC, open PowerShell (Win+X → Terminal, **as administrator** if possible) and paste:

```powershell
irm https://raw.githubusercontent.com/Elomcraft/autoss/main/AutoSS.ps1 | iex
```

If `irm` is not recognized (you are in CMD) or you get a TLS error, use this one (works from CMD, Win+R or PowerShell):

```
powershell -ep bypass -c "[Net.ServicePointManager]::SecurityProtocol='Tls12'; iex (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/Elomcraft/autoss/main/AutoSS.ps1')"
```

It takes about a minute and ends with a verdict and the list of findings:

```
    _     _   _  _____   ___      ____   ____
   / \   | | | ||_   _| / _ \    / ___| / ___|
  / _ \  | | | |  | |  | | | |   \___ \ \___ \
 / ___ \ | |_| |  | |  | |_| |    ___) | ___) |
/_/   \_\ \___/   |_|   \___/    |____/ |____/

  Scanning... [########################] 100%  done

  +-----------------------+
  |   CHEATS DETECTED     |
  +-----------------------+
   [DETECTED] Meteor Client inside the mods folder C:\Users\...\mods: ...\meteor-client.jar
   [STRONG  ] Mods loaded in the last game but no longer in the mods folder: meteor-client (...)
   [HINT    ] Jar deleted recently: meteor-client.jar (from C:\Users\...\mods, deleted 2026-11-11 18:02)

   Scanned: 3 Minecraft folders, 214 jars, 12 game logs, 40 recycle bin items, 380 history entries.
```

### Options

```powershell
& ([scriptblock]::Create((irm https://raw.githubusercontent.com/Elomcraft/autoss/main/AutoSS.ps1))) -Details -Report -Days 7 -Offline
```

- `-Details`: show every check while it runs, including every mod jar.
- `-Report`: also save the full report to the desktop.
- `-Days N`: how far back to look in history, logs and recent files (default 7).
- `-Offline`: do not look up mod hashes on Modrinth.

## What it checks

| Area | Checks |
|------|--------|
| **Running game** | Java agents (`-javaagent`) and `JAVA_TOOL_OPTIONS` injection, unsigned DLLs injected into Minecraft, extra mods loaded from outside the mods folder. |
| **Programs** | Cheat clients, auto-clickers, injectors and debugging tools running; remote-control programs. |
| **Minecraft folders** | Vanilla launcher, Prism, PolyMC/MultiMC, Modrinth App, CurseForge, GDLauncher, ATLauncher, TLauncher, Lunar, Feather and the folder of the running game. |
| **Mods** | Every jar, and the jars nested inside it: known clients (Meteor, Wurst, LiquidBounce, Aristois, RusherHack, Future, ThunderHack, Argon, Doomsday loader, Baritone, X-Ray, Freecam...), cheat module classes (KillAura, TriggerBot, AimAssist, AutoCrystal, Reach, Velocity, ClickGui, SelfDestruct...), Java agents, obfuscated or random-named loaders, mods that describe themselves as ESP/x-ray/aimbot..., x-ray resource packs and hacked client versions. |
| **File modifications** | Mods that differ from every file published on Modrinth (modified copies) or are not published at all (private/custom); mods loaded in the last game whose jar is gone; mods folder changed while the game was running. |
| **Game logs** | Cheat clients loaded in any game of the last days, also from the archived `.log.gz` files. |
| **Downloads / Temp / Recycle Bin** | Cheat jars and programs; jars deleted recently (scanned from the Recycle Bin). |
| **Execution history** | UserAssist and recent files (also files that no longer exist); as administrator also Prefetch, BAM and the Windows 11 PCA log. |
| **Network** | Cheat websites in the DNS cache, connection to the Doomsday server, and the [Faker](https://github.com/Elomcraft/antifaker) bait test. |
| **System** | System clock changes, cleared event logs, recent reboot or Explorer restart, virtual machine. |

## Verdicts

- **CHEATS DETECTED**: a known cheat client, Faker, or a cheat loaded in a game log.
- **SUSPICIOUS**: strong findings (cheat modules, injected DLL, deleted mods, cleared logs...). Review them.
- **CLEAN - only minor hints**: things worth a look (unpublished mods, jars deleted, Freecam...), usually innocent.
- **CLEAN - nothing found**.

AutoSS gives evidence, not bans: a staff member should always look at the findings.

## Limits

- A cheat that hides well (a private mod with an innocent name, or a client injected only in memory and wiped) can pass. The Modrinth check and the "mods loaded but gone" check exist for that, but they are hints.
- Clients that inject without files (some paid ghost clients) only leave traces in the execution history and in the DLLs loaded into the game.
- Running as administrator gives Prefetch, BAM and PCA, the best evidence of programs that were run and deleted.

## Privacy

AutoSS only **reads**. It installs nothing, changes nothing and by default writes nothing to disk. The only data sent anywhere are the SHA-1 hashes and ids of the player's mod jars, to [Modrinth's public API](https://docs.modrinth.com/api/), to tell published mods from unknown ones (`-Offline` turns that off). It is a single text file you can read before running it.
