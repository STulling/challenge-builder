# CTF Challenge Builder

A tool to build challenge images and create OCI deployment packages for CTF (Capture The Flag) challenges.

## Installation

Install via pipx:

```bash
pipx install git+https://github.com/STulling/challenge-builder.git
```

## Usage

Run from within a challenge directory that contains `docker-compose.yml` and `challenge.yml`:

```bash
build-challenge --ctfd-url <ctfd-url>
```

For classic (non-IaC) dynamic challenges you can omit `docker-compose.yml`; the builder will skip image/OCI packaging and only perform the CTFd synchronisation.

`<ctfd-url>` should be the full URL where the challenge will run (for example, `https://web.ctf.example` or simply `web.ctf.example`). The tool will automatically extract the subdomain and base domain from this URL.

### Auto-Update Check

When you run the tool, it automatically checks GitHub for newer versions and notifies you if an update is available. To upgrade:

```bash
pipx upgrade ctf-challenge-builder
# or reinstall from GitHub
pipx install --force git+https://github.com/STulling/challenge-builder.git
```

### Sync with CTFd

Provide CTFd credentials through CLI flags or environment variables to push dynamic or `dynamic_iac` challenges after the OCI package is built:

```bash
build-challenge \
  --ctfd-url https://mychal.ctf.example \
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
    mana_cost: 3
    timeout: 900
    additional:
      cpu: 2
      env.FLAG: "FLAG_PLACEHOLDER"
```

The `bundle.include` list can contain files or directories relative to the challenge root; the builder zips them into `dist/<slug>-<hash>.zip` where `<hash>` is the first eight characters of the archive’s SHA-256. The slug defaults to `bundle.slug`, then `ctfd.slug`, and finally the challenge name. That archive is uploaded automatically (the visible filename in CTFd can be overridden with `bundle.name`). Fields such as `mana_cost` and `timeout` inside the `dynamic_iac` block are forwarded directly to chall-manager so instance lifetimes behave as expected. Keys inside `dynamic_iac.additional` that start with `env.` become container environment variables at launch time; set the real flag value from the CTFd admin panel after the first sync so it never lands in the offline bundle.

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
