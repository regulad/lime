# lime privacy policy

*Effective 25 November 2026. Publisher: Parker Wahle, regulad@regulad.xyz.*

lime runs on a Linux host and unlocks FileVault-encrypted Macs on the same network when they restart, by answering macOS's pre-boot SSH unlock with each Mac's unlock password (README.md).

## Your Macs' details stay on this host

lime reads its configuration, the Macs' host keys and their passwords on the Linux host, and sends each password only to the Mac it belongs to, over SSH, once that Mac has proved who it is with its host key. It doesn't send the passwords, the configuration, or anything about your Macs anywhere else.

## Diagnostics

To find and fix problems, lime's releases send crash reports and usage counts to Sentry (Functional Software, Inc., sentry.io), a service that stores them on our behalf, in the United States. A build of lime from its source code sends nothing: it doesn't even contain the code that would.

- **Crash reports:** where in lime's code a crash happened, and which libraries lime had loaded (their file names and versions), so that the place can be found in them.
- **Usage counts:** one record for each start of lime, and whether it stopped on an error; and one for each password lime sends to a Mac at the pre-boot unlock, with how long it took and whether the Mac took it (`unlocked`) or turned it down (`refused`).
- **This host:** lime's version and the Rust version it was built with, and the Linux host's kernel (its name, release and build, as `uname` gives them) and processor architecture.

Each start of lime gets a random ID, made when it starts and never stored, so that a crash can be told apart from another start's. lime doesn't send the names you give the Macs, their network names or addresses, their host keys, the unlock accounts or their passwords, the network interfaces, its configuration, its log, this host's name, or anything else that identifies you, your Macs or this host, and our diagnostics service is set not to store IP addresses. It does note roughly where each report came from (the city, region and country), which it works out from the connection before discarding the address.

This is used only to diagnose and improve lime. It isn't sold, shared for advertising, or combined with other data. Sentry keeps it for up to 90 days.

## Turning diagnostics off

Set the environment variable `DO_NOT_TRACK` to `1` in lime's service (any value but empty, `0` or `false` will do), and lime sends nothing from its next start:

```sh
sudo systemctl edit lime       # add, under [Service]: Environment=DO_NOT_TRACK=1
sudo systemctl restart lime
```

## Children

lime isn't directed at children and doesn't knowingly collect children's personal information.

## Contact

Questions: regulad@regulad.xyz.

## Changes

We'll update this page, and its effective date, if any of this changes.
