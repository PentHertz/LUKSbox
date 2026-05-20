# LUKSbox trademark policy

"LUKSbox", the LUKSbox logo, "Penthertz", and the Penthertz logo
(collectively, the "Marks") are trademarks of **Penthertz**
(<https://penthertz.com>, <https://x.com/PentHertz>).

The source code is licensed under the
[Apache License, Version 2.0](LICENSE), which is OSI-approved open
source. Apache 2.0 explicitly does NOT grant trademark rights
(Section 6 of the License): you can fork the code, modify it, and
ship it under any name *except* "LUKSbox" or anything implying
endorsement by Penthertz. This policy is the operational detail of
that trademark reservation.

## What you can do without asking

- **Use the official binaries.** Download, install, and run the
  unmodified binaries we publish (the `.dmg`, `.msi`, `.tar.gz`,
  `.zip`) for any purpose. No attribution required beyond the
  existing notices the binaries already display.
- **Redistribute unmodified binaries.** Mirror the official archives
  bit-for-bit, host them on your own download server, ship them in
  a Linux distro package whose contents are exactly the upstream
  release. The Marks come along with the unmodified work.
- **Talk about LUKSbox.** Reference "LUKSbox" in articles, blog
  posts, talks, tutorials, training materials, comparison reviews,
  bug reports, social-media posts. Nominative use ("works with
  LUKSbox", "LUKSbox vs. competitor X") is fine and does not require
  permission.
- **Build LUKSbox from source for your own use.** Personal builds
  are fine.
- **Build a competing product from the source.** Apache 2.0 permits
  this. You must rename and re-brand (see below); the name and
  logo are reserved, the code is not.
- **Contribute.** Submit issues, pull requests, or patches under
  Apache 2.0 (the "Submission of Contributions" clause, Section 5,
  applies automatically; no separate CLA is required).

## What requires renaming

You **must rename and re-brand** before redistributing if you do
any of the following:

- **Modify the source.** Any change to the code (other than
  packaging metadata such as install paths or distro-policy patches)
  means the binary you distribute is a derivative work, not LUKSbox.
  Pick a different name (e.g. "FooVault", "MyOrg-Vault") and remove
  the LUKSbox logo, the LUKSbox name from the GUI / About view /
  docs, and the `com.penthertz.luksbox` reverse-DNS identifiers
  from the `.app` bundle, `.desktop` file, and MIME-type
  registrations.
- **Repackage and re-distribute.** If you bundle LUKSbox into a
  larger product or "appliance" and ship it as a unit, the unit
  cannot be called "LUKSbox" or use the Penthertz name or logo as
  if it were an official Penthertz product.
- **Fork the project.** A long-running fork that diverges from
  upstream cannot continue to use the LUKSbox name. Pick a fork
  name; you keep all the Apache 2.0 rights to the code.
- **Run a competing service.** You can run a hosted service built
  on LUKSbox source (Apache 2.0 allows it), but you cannot present
  it as "the LUKSbox service" or imply it is operated by Penthertz.
  Penthertz operates its own hosted service (the LUKSbox Hub); a
  competing service must use its own brand.

In all rename cases, the resulting product **must not imply
endorsement** by Penthertz. Phrases like "based on LUKSbox" or
"originally derived from LUKSbox" are fine; "LUKSbox by FooCorp",
"official LUKSbox build", or "LUKSbox, a FooCorp product" are not.

## What is never allowed

- Using the LUKSbox or Penthertz name in a way that could mislead
  users into thinking your product, service, or company is operated
  by, sponsored by, or affiliated with Penthertz when it is not.
- Registering the LUKSbox or Penthertz names as your own trademark
  in any jurisdiction.
- Registering domain names, social-media handles, app-store
  publisher names, or package-registry namespaces (Cargo crates,
  npm scopes, Docker Hub orgs, Homebrew tap names, etc.) that
  include "LUKSbox" or "Penthertz" with the intent of impersonating
  the project or trading on its reputation.
- Using the LUKSbox or Penthertz logos in their official forms on
  anything that is not an unmodified upstream release. Logos may
  be used in nominative contexts (a screenshot of the GUI, a slide
  deck about the project) but not as a brand for your own work.

## Asking

If you want to do something this policy doesn't clearly allow, or
if you want to license use of the LUKSbox name for a derivative
product or service, ask:
<https://penthertz.com> / <security@penthertz.com>. We're
happy to discuss case-by-case arrangements when the use is in good
faith.

## Why this matters

Penthertz publishes LUKSbox under Apache 2.0 so that anyone can
audit the cryptography, integrate it into other tooling, and depend
on it without lock-in. The Apache license is deliberately permissive
about the *code* - including for commercial competitors - because
the cryptography only earns trust when it can be inspected and
re-used freely.

What the license deliberately does not give away is the **brand**.
Trust in an encryption tool depends on knowing who maintains it,
who has push access, and who you would call when a bug is found.
The trademark policy keeps "LUKSbox" pointing at Penthertz so users
can tell the upstream project apart from any downstream fork or
re-bundle. That is also the safety net that protects the integrity
of the LUKSbox ecosystem as a whole.
