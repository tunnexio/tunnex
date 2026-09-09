# Official CLI repository submissions

Status: preparation authorized on 2026-09-09; no official submission sent.
Existing first-party repositories continue serving users.

## Homebrew core readiness

Live GitHub API: canonical upstream `tunnexio/tunnex` was created
2026-08-13T15:41:30Z and currently has 0 stars, 0 forks and 0 subscribers.
Search for `tunnex-cli` in Homebrew/homebrew-core issues returned zero results.

The current policy normally requires an owner submission to have 225 stars,
90 forks or 90 watchers, and normally excludes repositories under 30 days old.
Both normal eligibility checks are unmet today. Exceptions are at maintainer
discretion; no public adoption evidence supporting an exception has been supplied.
Do not represent the tested tap formula as an accepted core formula.

Candidate: `deploy/cli-distribution/homebrew-tap/Formula/tunnex-cli.rb`.
Before submission, run core-specific audit/style and its supported test matrix,
use an upstream stable release source, and exercise real CLI behavior in the
formula test beyond help/version. Existing tap CI does not prove core acceptance.
No core PR opened while eligibility is unresolved.

Policy: https://docs.brew.sh/Package-Acceptance-Policy
Formula rules: https://docs.brew.sh/Acceptable-Formulae

## Debian and Ubuntu submission draft

The maintainer name/email and account are pending user input. This draft must
not be sent with placeholders. Check WNPP and archive collisions directly before
filing; search-engine results alone did not establish absence.

```text
To: submit@bugs.debian.org
Subject: ITP: tunnex-cli -- command-line client for Tunnex networking

Package: wnpp
Severity: wishlist
Owner: <confirmed public maintainer name and email>

* Package name: tunnex-cli
  Version: 0.1.25
  Upstream Author: <confirmed public upstream contact>
* URL: https://github.com/tunnexio/tunnex
* License: Apache-2.0 (CLI; source-package copyright audit pending)
  Programming Lang: Go
  Description: command-line client for Tunnex networking

Tunnex CLI communicates with a Tunnex control plane. It provides authentication,
administrative commands and device tunnel commands. Tunnel operation uses the
host's WireGuard tools. Installing the CLI does not enroll a device or start a
tunnel. The CLI source is in apps/cli; the executable is named tunnex.

<Confirmed maintainer's maintenance and sponsorship plan>
```

This is an ITP draft, not a tested Debian source package. Existing nFPM DEBs
wrap upstream binaries; archive submission needs Debian source packaging,
dependency availability analysis (Go 1.25.13 and the CLI's Go modules), offline
build verification, copyright review excluding unrelated proprietary monorepo
components, lintian checks, a registered signing identity and sponsor review.
Never reuse repository automation's private signing identity as a personal
maintainer identity by assumption.

Prefer Debian-first for Ubuntu; acceptance and release import timing determine
availability. A PPA still requires users to add a repository and does not solve
the fresh-machine short-command requirement.

Process: https://mentors.debian.net/intro-maintainers/
Ubuntu: https://wiki.ubuntu.com/UbuntuDevelopment/NewPackages

## Fedora follow-up

Need confirmed maintainer account/contact and source RPM packaging/review;
existing binary-wrapper RPM is not evidence of archive acceptance. Verify the
current Fedora maintainer onboarding and Go packaging requirements before
preparing a spec/SRPM. The official onboarding page returned an access-denied
challenge during this pass, so its contents were not verified.

https://docs.fedoraproject.org/en-US/package-maintainers/Joining_the_Package_Maintainers/

Fedora acceptance would not automatically publish to every RHEL derivative or
older release. EPEL and each other archive have their own scope and review.

## Outstanding input and boundaries

- Public maintainer name/email; existing Debian/mentors, Fedora and Launchpad
  usernames. No passwords or private keys in chat.
- Homebrew normal eligibility is an external blocker, not a missing Git login.
- No account terms accepted or maintenance commitment made for an unnamed person.
- No changes to live distribution workflows, source versions or release tags.
