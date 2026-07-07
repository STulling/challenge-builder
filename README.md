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

The builder derives the OCI registry host automatically:
- `event.ctf.place` → `registry.ctf.place`
- `event.com` → `registry.event.com`

If your setup uses a different registry hostname, pass `--oci-registry <host>` or set `OCI_REGISTRY`.

For classic (non-IaC) dynamic challenges you can omit `docker-compose.yml`; the builder will skip image/OCI packaging and only perform the CTFd synchronisation.

For multi-task challenges, use the `multi_dynamic` challenge type and define a
`tasks` list. Each task defines a weight. Players see points calculated from
the current dynamic challenge value and each task's fraction of the total
weight:

```yaml
name: Three Questions
category: Misc
type: multi_dynamic
description: Answer all three questions.
initial: 500
minimum: 50
decay: 50
function: linear
tasks:
  - name: Question 1
    description: |
      Inspect the archive.
      Submit the first flag you find.
    weight: 1
    input_template: "FLAG{first}"
    flag:
      type: static
      content: FLAG{first}
  - name: Question 2
    weight: 1
    input_template: "Enter a lowercase word"
    flag:
      type: regex
      content: "[a-z]+"
  - name: Question 3
    weight: 2
    input_template: "FLAG{third}"
    flag:
      type: static
      content: FLAG{third}
```

With weights `1`, `1`, and `2`, the first two tasks each show and award 25% of
the challenge's current dynamic value, and the third shows and awards 50%. If
`tasks` is present and `type` is omitted, the builder uses `multi_dynamic`. The
`input_template` value controls the placeholder shown in the task's answer
field. Task flags use CTFd's normal flag types, including `static` and `regex`;
regex flags use `content` as the regular expression and may set
`data: case_insensitive`.

Regular challenge flags may be strings or objects. Object flags support CTFd's
normal `data` field and the aliases `format_hint`, `formatHint`, `format`, and
`placeholder`, which are forwarded as flag data:

```yaml
flags:
  - FLAG{simple_static_flag}
  - content: FLAG{case_insensitive_flag}
    type: static
    data: case_insensitive
  - content: FLAG{...}
    type: static
    format_hint: "FLAG{...}"
```

### Challenge.yml format example

Define the challenge payload inside `challenge.yml` under a `ctfd` key. Example for a `dynamic_iac` challenge:

```yaml
# General stuff:
name: Artis
category: Web
type: dynamic_iac # dynamic_iac uses infrastructure as code + dynamic scoring, just use `dynamic` for offline challenges
description: | 
  I love visiting Artis, the zoo here in Amsterdam. \
  They have so many amazing animals there!
attribution: Simon
state: visible # defaults to visible if ommitted, alternative is `hidden`
slug: artis # you can provide a custom slug here, otherwise it will be generated from the challenge name
tags:
  - easy 
bundle: # what files will be available to the user
  include:
    - database/
    - website/
    - docker-compose.yml
flags:
  - content: FLAG{I_l1ke_gophers_I_kn0w_4rt1s_h4s_a_f3w}
    type: static
    format_hint: "FLAG{...}"

# Stuff for challenge deployment
is_http: true # if removed it will default to False
initial: 500 # initial score, defaults to 500
minimum: 50 # minimum score, defaults to 50
decay: 50 # decay, defaults to 50
function: linear # use either the linear or logarithmic scoring formula, defaults to linear
dynamic_iac:
  timeout: 1800 # time in seconds for which the challenge will be online, defaults to 1800 (30 minutes)
  mana_cost: 0 # how much mana it costs to start a challenge, defaults to 0
  min: 10 # minimum number of pre-provisioned instances, defaults to 10
  max: 20 # number of instances to stop pre-provisioning at, defaults to 20
  entrypoints: # optional: player-facing endpoints to show for this instance
    - name: Website
      prefix: web
      service: app
      port: 8080
      protocol: HTTP
    - name: Admin
      prefix: admin
      service: app
      port: 9000
      protocol: HTTP
  additional: # additional variables to add to the dockerfiles when building
    env.FLAG: "FLAG{I_l1ke_gophers_I_kn0w_4rt1s_h4s_a_f3w}"
```

A very minimal challenge could be:
```yaml
name: Artis
category: Web
type: dynamic_iac
description: | 
  I love visiting Artis, the zoo here in Amsterdam. \
  They have so many amazing animals there!
attribution: Simon
tags:
  - easy 
bundle:
  include:
    - database/
    - website/
    - docker-compose.yml
  skip_flag_check: true # optional: allow known flag strings in bundled files
flags:
  - content: FLAG{I_l1ke_gophers_I_kn0w_4rt1s_h4s_a_f3w}
    type: static
    format_hint: "FLAG{...}"
recreate_on_type_change: true # optional: delete/recreate if CTFd has this challenge under a different type
is_http: true 
dynamic_iac:
  additional:
    env.FLAG: "FLAG{I_l1ke_gophers_I_kn0w_4rt1s_h4s_a_f3w}"
```

The `bundle.include` list can contain files or directories relative to the challenge root; by default the builder zips them into `dist/<slug>-<hash>.zip` where `<hash>` is the first eight characters of the archive’s SHA-256. That archive is uploaded automatically.

When a bundled `docker-compose.yml` or `docker-compose.yaml` is included for players, the builder strips deployment-only protocol suffixes from `ports:` entries before upload. Suffixes `/HTTP`, `/TCP`, `/http`, and `/tcp` are removed only from compose `ports:` values. The source compose file is not modified.

If the bundle should upload existing files instead of a generated zip, set `bundle.zip` to `false` and list the files:

```yaml
bundle:
  zip: false
  include:
    - handout.pdf
    - source.py
```

In direct-file mode the builder uploads each file as-is and uses each file's own name, such as `handout.pdf` and `source.py`. `bundle.name` can still override the upload name when exactly one direct file is included.

If direct-file mode includes `docker-compose.yml` or `docker-compose.yaml`, the sanitized upload copy is written to `dist/<slug>-bundle/docker-compose.yml` so the challenge source file remains unchanged.

### Dynamic IaC entrypoints

For `dynamic_iac` challenges, append `/HTTP` or `/TCP` to compose `ports:` values that should be exposed to players. Uppercase suffixes are player-facing; lowercase suffixes are still routed but hidden from the player connection info. For example:

```yaml
services:
  app:
    ports:
      - "8080/HTTP"
      - "9000/TCP"
      - "9100/tcp"
```

By default, every uppercase compose port is shown to players. HTTP endpoints are shown as `https://host`; TCP endpoints are shown as `ncat --ssl host port`.

Set `dynamic_iac.entrypoints` to control exactly which service/port pairs are shown and to give them readable host prefixes:

```yaml
dynamic_iac:
  entrypoints:
    - name: Website
      prefix: web
      service: app
      port: 8080
      protocol: HTTP
    - name: Admin
      prefix: admin
      service: app
      port: 9000
      protocol: TCP
```

With entrypoints configured, players see only those endpoints. Generated hosts use the configured prefix, such as `web-<instanceid>.<ctf-domain>` and `admin-<instanceid>.<ctf-domain>`. If `entrypoints` is omitted, the builder falls back to all uppercase `/HTTP` and `/TCP` compose ports.

When `entrypoints` is set, compose ports may omit `/HTTP` or `/TCP` suffixes because the player-facing endpoint list is explicit. Add `protocol: HTTP` or `protocol: TCP` to an entrypoint when the compose port has no suffix; otherwise protocol-less ports default to TCP routing.

By default, the builder refuses to update an existing CTFd challenge if its stored type differs from `challenge.yml`, because CTFd cannot safely migrate challenge subclass tables with a normal PATCH. Set `recreate_on_type_change: true` in `challenge.yml`, pass `--recreate-on-type-change`, or set `CTFD_RECREATE_ON_TYPE_CHANGE=1` to delete the existing challenge and create a fresh one with the requested type. This changes the challenge ID and removes the old challenge's solves, files, hints, and related state.

Fields such as `mana_cost` and `timeout` inside the `dynamic_iac` block are forwarded directly to chall-manager so instance lifetimes behave as expected. Keys inside `dynamic_iac.additional` that start with `env.` become container environment variables at launch time.
