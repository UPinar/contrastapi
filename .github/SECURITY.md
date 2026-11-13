# Security policy

## Report a vulnerability

Please do not open a public issue for a security problem.

Report it privately in one of two ways:

- GitHub: open the **Security** tab of this repository and choose **Report a vulnerability**.
- Email: contact@contrastcyber.com, with "security" in the subject.

Tell us what you found, how to reproduce it, and what an attacker could do with it.
A proof of concept helps. Please do not test against other people's data, and do not run
tests that slow the hosted service down for its other users.

We answer each report, and we tell you when the fix ships. If you want, we name you in
the fix notes.

## Scope

In scope:

- The server code in this repository.
- The hosted service at `api.contrastcyber.com`.

Out of scope:

- The data the service serves. It comes from public sources, and a wrong entry there
  belongs to its source.
- The SDKs and extensions. Report those in
  [contrastapi-clients](https://github.com/UPinar/contrastapi-clients).
- Rate limits that work as documented, and reports that need only a high request volume.

## Supported versions

Security fixes reach the hosted service first. They are then published to the `main` branch.
