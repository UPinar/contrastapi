# Contributing to ContrastAPI

Thank you for your interest. Bug reports, fixes and new tests are welcome.

## Before you start

- **Security problems** go through [SECURITY.md](SECURITY.md), not a public issue.
- **A wrong data entry** usually belongs to its source, such as NVD or OSV. Open an issue
  here only when the server changes or drops the value the source holds.
- **A new endpoint or a large change:** open an issue first and describe it. An endpoint
  has a credit cost and its own docs, and most endpoints are MCP tools too. So its shape is
  agreed before the code.

## Contributor License Agreement

A pull request can be merged only after you sign the
[Contributor License Agreement](CLA.md). The CLA Assistant bot asks you on your first pull
request, and you sign it once with your GitHub account.

Under the agreement you keep the copyright of your work. You give the maintainer a license
to use and distribute it, which includes the right to offer the code under other licenses
as well as the AGPL.

## Build and test

The server builds on Linux with GCC. On Debian or Ubuntu:

```sh
sudo apt-get install -y gcc g++ make pkg-config libpq-dev libssl-dev libcurl4-openssl-dev
make                                     # must build with no warning
make test                                # C unit tests, no database
make clean && make test SANITIZE=1       # the unit tests under ASan and UBSan
```

The SQL tests run on PostgreSQL. CI uses PostgreSQL 16. `make test-sql` runs as a superuser
on an empty database:

```sh
psql -X -d postgres -f sql/roles.sql      # once per cluster, as a superuser
createdb contrastapi_test
make test-sql DB_TEST=contrastapi_test
```

CI runs these and more: cppcheck, a TSan run, the fuzz seeds, and checks that the docs,
the column lists and the grants agree with the code. A pull request needs a green CI run.

## What a change needs

- **A test.** A fix comes with a test that fails without it. Write the test first.
- **No SQL text in `src/`.** The server reads the database only through the `api.fn_*`
  functions of `sql/`. Each value goes in its own bind parameter.
- **The schema version.** A change to an api function in `sql/fn_*.sql` raises both
  `api.fn_schema_version` and `DB_REQUIRED_SCHEMA_VERSION` in `src/db.h`. CI compares them.
- **The docs.** A change that a client can see, such as a field, a status code or a credit
  cost, updates [docs/API_Documentation.md](../docs/API_Documentation.md) and, for a tool,
  [docs/MCP_Documentation.md](../docs/MCP_Documentation.md).
- **One subject per pull request.** A fix and a cleanup are two pull requests.

## Style

- C17 with GNU extensions (`-std=gnu17`), compiled by GCC.
- Names follow the code around them: `module_camelCase` for a public function,
  `static_camelCase` for a file-local one, `ModuleName_t` for a type.
- A pointer's `*` sits next to the type: `char* name`.
- Comments use `/* */`, never `//`.
