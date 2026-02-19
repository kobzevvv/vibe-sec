# Contributing to vibe-sec

Thanks for your interest in improving security for AI coding agents.

## Getting Started

```bash
git clone https://github.com/kobzevvv/vibe-sec.git
cd vibe-sec
npm install
```

## Development

```bash
# Run scanner (static checks only)
npm run scan-logs:static

# Run report server
npm run report

# Install hook guard locally
npm run install-hooks

# Run dirty machine tests
./test/dirty-machine/setup-macos.sh
npm run scan-logs:static
./test/dirty-machine/teardown.sh
```

## Pull Request Guidelines

1. **One concern per PR** — don't mix features with bug fixes
2. **Test your changes** — run `npm run scan-logs:static` before submitting
3. **Security-critical changes** — if your PR affects hook.mjs or detection patterns, explain the security implications
4. **No secrets** — never commit real credentials, even in tests. Use obviously fake values with `TESTFIXTURE` markers

## Code Style

- ES modules (`import`/`export`)
- Minimal dependencies (prefer Node.js built-ins)
- Functions should be under 100 lines where possible
- Comments for non-obvious security logic

## Areas Where Help Is Needed

- **Windows support** — see [issue #8](https://github.com/kobzevvv/vibe-sec/issues/8)
- **New detection patterns** — if you find a secret format we don't catch
- **False positive reports** — if a legitimate command gets blocked
- **Documentation** — improving examples and guides

## Security Vulnerabilities

If you find a security vulnerability, do NOT open a public issue. See [SECURITY.md](SECURITY.md).
