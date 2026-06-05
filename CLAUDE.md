# CLAUDE.md

GDPR-konformer Audit-Logger für PHP (Library, `zappzarapp/audit-logger`).

## Schwesterprojekt — konsistent halten

`zappzarapp-node-audit-logger` ist das Node/TypeScript-Pendant mit gleichem Funktionsumfang.
Bei Änderungen an CI, Tooling-Philosophie oder Projektstruktur immer das jeweils
andere Repo abgleichen, damit beide in Aussage und Aufbau gleich bleiben.

Beispiel: Der Security-Audit liegt in beiden Repos in einem **eigenen `security`-CI-Job**
(nicht inline in der Test-Matrix). PHP `composer audit --no-dev` entspricht bewusst
Nodes `pnpm audit --prod`: nur Runtime-/Produktiv-Deps sind CI-blockierend, die
dev-Toolchain ist über Dependabot, Socket, GitGuardian, CodeQL und Psalm Taint abgedeckt.

## Composer-Audit-Falle (wichtig)

Diese Library hat **keine Runtime-Composer-Dependencies** — `require` ist nur
`php` + `ext-pdo` (Plattform-Constraints, keine Pakete). Daher ist die non-dev-Paketmenge
leer, und Composer bricht bei einer leeren Menge ab:

```
composer audit --no-dev
> No installed packages found. ... (exit 1)
```

`--locked --no-dev` hilft hier **nicht** (Composer fällt bei leerer non-dev-Menge auf
den installed-Pfad zurück). Lösung: vorher prüfen, ob es überhaupt Runtime-Deps gibt,
und die leere Menge wie Nodes `pnpm audit --prod` grün durchlaufen lassen.

Diese Guard-Logik lebt in **`scripts/security-audit.sh`** als *Single Source of Truth*:
Sowohl das composer-Script `security` (`bash scripts/security-audit.sh`, aufgerufen von
`composer check`/`check-full`) als auch der CI-Job `security` (`run: composer security`)
führen dieses eine Script aus — lokale und CI-Checks können also nicht auseinanderlaufen.
Bei Änderungen an der Audit-Logik nur dieses Script anfassen.

## Konventionen

- Conventional Commits (`type(scope): message`), z. B. `ci:`, `chore(deps-dev):`.
- Commits müssen **GPG-signiert** sein (CI-Job `Verify GPG Signatures` erzwingt das).
- Dependabot-PRs für dev-Deps werden gruppiert (`.github/dependabot.yml`, wöchentlich)
  und nach grünem CI automatisch gemergt.
