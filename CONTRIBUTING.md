# Contributing to zappzarapp/audit-logger

Thank you for your interest in contributing!

## Development Setup

```bash
git clone git@github.com:marcstraube/zappzarapp-php-audit-logger.git
cd zappzarapp-php-audit-logger
make install
make hooks
```

## Git Hooks (Captainhook)

Git hooks are managed via
[Captainhook](https://captainhookphp.github.io/captainhook/).

| Hook           | Actions                                            |
| -------------- | -------------------------------------------------- |
| `commit-msg`   | Validate Conventional Commits format               |
| `pre-commit`   | Block secrets, PHP syntax check, CS-Fixer auto-fix |
| `pre-push`     | Run all quality checks (`make check`)              |

Hooks are configured in `captainhook.json`.

## Running Tests

```bash
make check       # Run all checks (security, style, analysis, architecture, tests)
make check-full  # Run all checks including mutation testing
make test        # Run only tests
make infection   # Run mutation testing
make deptrac     # Run architecture analysis
```

## Local Development with PHP 8.4

For mutation testing with pcov, install PHP 8.4 with required extensions:

```bash
# Arch Linux (AUR)
paru -S php84 php84-cli php84-ctype php84-curl php84-dom php84-iconv \
        php84-mbstring php84-opcache php84-openssl php84-phar php84-simplexml \
        php84-tokenizer php84-pcov php84-xml php84-xmlwriter

# The Makefile uses php84 by default
make infection   # Uses php84 with pcov
```

## Code Quality

All contributions must pass:

- PHPStan level 8
- PHPMD checks
- Rector suggestions
- PHP-CS-Fixer style
- Deptrac architecture boundaries
- High test coverage for new code (>95%, excluding untestable I/O code)
- **100% mutation score** (Infection, enforced via `infection.json5`)

## Architecture Rules (Deptrac)

The codebase enforces layer boundaries:

```text
Exception     -> (no dependencies)
Encryption    -> Exception
CoreDTO       -> (no dependencies)
CoreInterface -> CoreDTO, Exception
CoreLogger    -> CoreInterface, CoreDTO, Encryption, Exception
CoreNullLogger -> CoreInterface, CoreDTO, Exception
```

Run `make deptrac` to verify architecture compliance.

## Commit Signing

**CRITICAL: All commits MUST be GPG-signed.**

This is enforced in CI/CD:

- GitHub Actions will fail on unsigned commits
- GitLab CI will fail on unsigned commits
- Pull requests with unsigned commits will be rejected

### Setup GPG Signing

```bash
# Generate GPG key
gpg --full-generate-key

# List keys
gpg --list-secret-keys --keyid-format=long

# Export public key
gpg --armor --export YOUR_KEY_ID

# Configure Git
git config --global user.signingkey YOUR_KEY_ID
git config --global commit.gpgsign true
git config --global tag.gpgSign true
```

### Add GPG key to GitHub

1. Go to <https://github.com/settings/keys>
2. Click "New GPG key"
3. Paste your public key

### Verify Signatures

```bash
# Verify commit
git verify-commit HEAD

# Verify tag
git verify-tag v1.0.0
```

## Pull Request Process

1. Fork the repository
2. Create a feature branch (`feature/your-feature`)
3. Make your changes
4. **Sign all commits** with GPG
5. Run `make check-full` - all checks must pass
6. Push to your fork
7. Create a Pull Request

### PR Requirements

- [ ] All commits are GPG-signed
- [ ] All tests pass (`make test`)
- [ ] Code style is clean (`make cs-check`)
- [ ] Static analysis passes (`make analyse`)
- [ ] No PHPMD violations (`make phpmd`)
- [ ] No Rector suggestions (`make rector`)
- [ ] Architecture rules pass (`make deptrac`)
- [ ] Mutation testing passes (`make infection`)
- [ ] Security audit passes (`make security`)
- [ ] New features have tests (high coverage, excluding untestable I/O)
- [ ] Documentation is updated

## Release Process

Releases are **fully automated** via
[release-please](https://github.com/googleapis/release-please).

### How it works

1. Review your PR (all commits must use
   [Conventional Commits](https://www.conventionalcommits.org/))
2. Merge PR to `master` branch
3. **release-please** automatically creates/updates a Release PR with:
   - Auto-generated CHANGELOG.md from commit messages
   - Version bump in composer.json
4. Review the Release PR (verify changelog, version bump, breaking changes)
5. Merge the Release PR (you must GPG-sign the merge commit)
6. **release-please** automatically creates:
   - GitHub Release
   - GPG-signed tag
   - Attaches SBOM to release

### Commit Message Format

Use [Conventional Commits](https://www.conventionalcommits.org/):

- `feat: add new feature` -> minor version bump (0.X.0)
- `fix: resolve bug` -> patch version bump (0.0.X)
- `security: fix vulnerability` -> patch + Security section in CHANGELOG
- `feat!: breaking change` -> major version bump (X.0.0)
- `chore:`, `docs:`, `ci:` -> no version bump (included in changelog)

### Manual Release (Emergency Only)

Only for hotfixes when automation fails:

1. Create signed tag: `git tag -s vX.Y.Z -m "Release vX.Y.Z"`
2. Push tag: `git push origin vX.Y.Z`
3. Manually update CHANGELOG.md and composer.json version
4. Create GitHub Release manually

## Security Vulnerabilities

**Do not report security vulnerabilities via public issues.**

See [SECURITY.md](SECURITY.md) for responsible disclosure process.

## Questions?

Open a discussion on GitHub or reach out via <email@marcstraube.de>
