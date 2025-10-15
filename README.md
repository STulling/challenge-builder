# CTF Challenge Builder

A tool to build challenge images and create OCI deployment packages for CTF (Capture The Flag) challenges.

## Installation

Install via pipx:

```bash
pipx install ctf-challenge-builder
```

## Usage

Run from within a challenge directory that contains `docker-compose.yml` and `challenge.yml`:

```bash
build-challenge --ctf-domain <ctf-domain>
```

For classic (non-IaC) dynamic challenges you can omit `docker-compose.yml`; the builder will skip image/OCI packaging and only perform the CTFd synchronisation.

`<ctf-domain>` should be the host where the challenge will run (for example, `web.ctf.example`); you may include an `https://` scheme if that is more convenient.

### Optional: Sync with CTFd

Provide CTFd credentials through CLI flags or environment variables to push dynamic or `dynamic_iac` challenges after the OCI package is built. `--ctfd-url` defaults to `https://<ctf-domain>` when omitted:

```bash
build-challenge \
  --ctf-domain mychal.ctf.example \
  --ctfd-url https://ctfd.example \
  --ctfd-token <api-token>
```

Equivalent environment variables: `CTFD_URL`, `CTFD_TOKEN`, `CTFD_USERNAME`, `CTFD_PASSWORD`, and `CTFD_VERIFY_SSL` (`true` by default). Supplying a token overrides username/password. Add `--ctfd-no-verify` if you need to skip TLS validation\*.

Define the challenge payload inside `challenge.yml` under a `ctfd` key. Example for a `dynamic_iac` challenge:

```yaml
name: Holiday Hack
category: Web
ctfd:
  type: dynamic_iac
  slug: holiday-hack
  tags: ["web", "holiday"]
  bundle:
    include:
      - public/
      - README.md
  flags:
    - content: flag{example}
      type: static
  challenge:
    name: Holiday Hack
    category: Web
    description: |
      Welcome to the holidays!
    state: hidden
    initial: 500
    minimum: 100
    decay: 50
  dynamic_iac:
    # scenario defaults to the OCI reference produced by the builder
    mana_cost: 1
    timeout: 900
    additional:
      cpu: 2
```

The `bundle.include` list can contain files or directories relative to the challenge root; the builder zips them into `dist/<slug>-<hash>.zip` where `<hash>` is the first eight characters of the archive’s SHA-256. The slug defaults to `bundle.slug`, then `ctfd.slug`, and finally the challenge name. That archive is uploaded automatically (the visible filename in CTFd can be overridden with `bundle.name`).

Example for a `dynamic` challenge that exposes a simple file bundle and static flag:

```yaml
name: Warmup
category: Misc
ctfd:
  type: dynamic
  slug: warmup
  bundle:
    include:
      - dist/writeup.txt
  flags:
    - content: flag{warmup}
      type: static
  challenge:
    description: |
      Grab the file and submit the flag.
    value: 100
    decay: 0
```

For classic dynamic challenges, set `type: dynamic` and (optionally) place any extra fields inside a `dynamic` block. When a `ctfd` section is present, the builder automatically hashes the payload plus attachments—including the generated bundle—and only updates the remote challenge when the hash changes.

\*Skipping TLS verification is discouraged; only use it for local development.

## Requirements

- Docker
- OCI CLI tools (e.g., `oras`)
- Go (for building the deployment program)

## Development

To install in development mode:

```bash
pip install -e .
```
