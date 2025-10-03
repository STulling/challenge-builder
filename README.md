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

## Requirements

- Docker
- OCI CLI tools (e.g., `oras`)
- Go (for building the deployment program)

## Development

To install in development mode:

```bash
pip install -e .
```