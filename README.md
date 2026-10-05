# lime

lime unlocks FileVault-encrypted Macs that restarted on their own, such as after a kernel panic or a power cut, so they come back without someone at the keyboard.

On macOS 26, an Apple silicon Mac with Remote Login on waits after a restart at a pre-boot stage. There, a small SSH server accepts a FileVault user's password and unlocks the disk. lime runs on an always-on Linux machine on the same network. It notices a Mac waiting there, checks by its host key that it really is that Mac, and answers with that Mac's password.

(Like [Tang](https://github.com/latchset/tang), but a fruit.)

## How it works, briefly

- **Watching:** lime asks systemd-resolved over Varlink to browse mDNS for SSH servers (`_ssh._tcp`), and connects to each one that appears.
- **Identifying the Mac:** Macs are identified by their pinned SSH host keys, not by name. The name a Mac announces over mDNS can differ from the one you gave it, and can change after a restart. A server whose host key isn't listed gets the handshake and nothing else. The pre-boot stage presents the same host keys as the booted Mac.
- **Logging in:** lime sends the unlock account's password to its one hidden prompt, and reads what the Mac does with it:
  - **At pre-boot**, the password unlocks the disk. Apple's SSH server says so with a login banner ("System successfully unlocked.") and then restarts the Mac into macOS, which tears the connection down — cleanly or with a hang, depending on the network. lime treats the banner, a close, or a hang after the password all as the unlock, and never mistakes any of them for a refusal (a wrong password always comes back as an explicit refusal).
  - **A booted Mac** accepts the password but lands the account nowhere: a drop-in restricts it to a login with no shell, no command and no forwarding. lime notices it was let in and leaves the Mac alone.
  - **A refused password** means a wrong stored password, which lime logs and retries on a doubling backoff. A drop-in that offers *only* keyboard-interactive marks a booted Mac, so lime can tell a booted Mac's quirks apart from a genuine pre-boot refusal.
- **Secrets:** the passwords are systemd credentials, encrypted to the Linux host's TPM and decrypted only into lime's private credentials directory.

## Requirements

**Macs**
- Apple silicon, macOS 26 or later, FileVault on, Remote Login on.
- At pre-boot, a MacBook is on the network only over Wi-Fi: USB Ethernet adapters need approval after login. Field reports say Wi-Fi at pre-boot works from macOS 26.5 on. Apple lists previously joined open or WPA2-Personal networks, and Ethernet without 802.1X.

**Linux host**
- On the same network segment as the Macs, since mDNS does not cross subnets.
- systemd-resolved with mDNS on for that interface, and a systemd new enough to have `io.systemd.Resolve.BrowseServices`. Developed against systemd 259.
- `systemd-creds` for the secrets. A TPM2 (a vTPM is fine) is recommended.
- Rust 1.88 or later to build.

## Setup

The examples call the Mac `mymac`. That's only a label you choose, used in lime's logs and its credential's name.

### 1. Install lime on the Linux host

```sh
cargo build --release
sudo install -m 0755 target/release/lime /usr/local/bin/lime
sudo install -m 0644 lime.service /etc/systemd/system/lime.service
sudo install -d /etc/lime
sudo install -d -m 0000 /etc/credstore.encrypted   # systemd's own mode for it; root still gets in
sudo install -m 0644 lime.example.toml /etc/lime/lime.toml
sudo install -D -m 0644 README.md /usr/local/share/doc/lime/README.md
```

### 2. On each Mac

#### a. A separate account that can only unlock the disk

Run this on the Mac, with your admin account's name in place of `YOUR_ADMIN`:

```sh
# An unguessable name: 16 random lowercase letters, such as cpgjspoegwgrmymc.
# Keep it: it goes into lime's config as unlock_user.
FVUSER=$(openssl rand -base64 96 | LC_ALL=C tr -dc 'a-z' | head -c 16); echo "$FVUSER"

# A standard user with no shell. Your admin credentials grant it a Secure Token.
sudo sysadminctl -addUser "$FVUSER" -fullName "FileVault unlock" -shell /usr/bin/false \
     -password - -adminUser YOUR_ADMIN -adminPassword -

# Check it got a Secure Token. If not, grant one, then re-run updatePreboot and fdesetup below:
sudo sysadminctl -secureTokenStatus "$FVUSER"
#   sudo sysadminctl -secureTokenOn "$FVUSER" -password - -adminUser YOUR_ADMIN -adminPassword -

# Let it through Remote Login, if that allows only some users.
if dscl . -read /Groups/com.apple.access_ssh RecordName >/dev/null 2>&1; then
    sudo dseditgroup -o edit -a "$FVUSER" -t user com.apple.access_ssh
    dseditgroup -o checkmember -m "$FVUSER" com.apple.access_ssh   # must say "yes …"
fi

# Hide it from the login window.
sudo dscl . -create "/Users/$FVUSER" IsHidden 1

sudo diskutil apfs updatePreboot /
sudo fdesetup list -extended          # the account must be listed

# Last, in System Settings › General › Sharing, keep the account out of Screen Sharing
# and File Sharing ("Allow access for: Only these users").
```

**Why it's set up this way**
- **A separate account:** any FileVault-enabled account can answer the pre-boot unlock; it doesn't have to be an administrator or the Mac's owner. A dedicated, hidden, standard account keeps your own password off the Linux host. Leaked, its password gives someone a decrypted Mac sitting at the login window: no Recovery, no admin, and no remote login.
- **A random name:** unknown account names fail without using up any of the Mac's limited password attempts, so 16 random lowercase letters, such as `cpgjspoegwgrmymc`, stop strangers on the network from burning them.
- **The Secure Token** is what lets the account unlock FileVault. Creating it with your admin's credentials grants one.
- **Remote Login:** on a booted Mac, lime logs in as this account to confirm the Mac is up (2b), so Remote Login must let it in. Its "Allow access for" list is the group `com.apple.access_ssh`, which exists only while access is limited to some users; under "All users" the `if` skips it. System Settings may not offer this account in that list at all, which is why it's added from Terminal.

When you change this account's password, do it with its old password or with your admin's, so FileVault stays in step. Then update its credential on the Linux host (section 3a) straight away. A wrong stored password costs one of the Mac's password attempts every time lime tries it at pre-boot.

#### b. Dead-end the account once the Mac is booted (required)

On a booted Mac, lime still logs in with the password to confirm the Mac is up. The account must land nowhere: no shell, no command, no forwarding. A drop-in does that, and restricts it to a password login (`keyboard-interactive`), which is also how lime tells a booted Mac from one at pre-boot:

```sh
sudo tee /etc/ssh/sshd_config.d/50-lime-unlock.conf <<EOF
Match User $FVUSER
    AuthenticationMethods keyboard-interactive
    KbdInteractiveAuthentication yes
    ForceCommand /usr/bin/false
    DisableForwarding yes
    PermitTTY no
EOF

sudo sshd -t                          # no output: the configuration is valid
sudo sshd -T -C user="$FVUSER" | grep -Ei '^(authenticationmethods|kbdinteractiveauthentication|forcecommand)'
#   must show: authenticationmethods keyboard-interactive
#              kbdinteractiveauthentication yes
#              forcecommand /usr/bin/false
```

`KbdInteractiveAuthentication yes` keeps this working on a Mac whose password logins you've turned off. `PasswordAuthentication no` alone leaves `keyboard-interactive` on, but it's usually paired with `KbdInteractiveAuthentication no` (or the older `ChallengeResponseAuthentication no`), and then the booted Mac would drop lime's connection before any password is sent, so lime could never see that it's up. The line turns password logins back on for this one account only, which the pre-boot server offers anyway (see Limitations); every other account keeps your settings. If `sshd -T` still shows `no`, a `Match` block of yours that sshd reads earlier sets it first: the first value sshd reads wins.

None of this reaches the pre-boot unlock. The file lives on the disk that is still locked at that point, and Apple's pre-boot SSH server uses only its own built-in settings. That's why the booted Mac offering only `keyboard-interactive`, while the pre-boot server offers its defaults, tells the two stages apart.

#### c. Collect its host keys

```sh
cat /etc/ssh/ssh_host_*_key.pub
```

Copy every line into the Mac's `host_keys` (section 3b). Take them from the Mac itself, or over a connection you already trust, rather than from an unverified `ssh-keyscan`.

### 3. Configure lime on the Linux host

#### a. One password per Mac

Each password is a credential named `lime.<name>`, matching the Mac's `name` in the config. Type it in with `systemd-ask-password`, which doesn't echo it or put it in your shell history:

```sh
systemd-ask-password -n "mymac unlock password:" \
  | sudo systemd-creds encrypt --with-key=host+tpm2 --name=lime.mymac - /etc/credstore.encrypted/lime.mymac

# Check it decrypts to the password you meant. -+F -+X make less use the alternate screen,
# which most terminals keep out of scrollback, even if $LESS says otherwise; q quits.
sudo systemd-creds decrypt /etc/credstore.encrypted/lime.mymac - | less -+F -+X
```

Any password manager's command-line tool can be piped in the same way instead of `systemd-ask-password`. One trailing newline in a credential is ignored. `--with-key=host+tpm2` binds the credential to this machine's TPM *and* its credential secret, so a copied file is useless anywhere else. Without a TPM, use `--with-key=host`.

#### b. The configuration

Edit `/etc/lime/lime.toml`; `lime.example.toml` explains each field. In short, add one `[[mac]]` entry per Mac with a label, its unlock account and all its host keys.

Make sure mDNS is on for the interfaces you list:

```sh
resolvectl mdns eth0       # must say "yes"
```

If it isn't, set `MulticastDNS=yes` in `/etc/systemd/resolved.conf` and turn it on for the link. For systemd-networkd that's `MulticastDNS=yes` in the `.network` file; for NetworkManager, `nmcli connection modify <conn> connection.mdns yes`.

#### c. A dry run first

Run lime once with `--dry-run`, under the same credentials and sandbox the service will use. It does everything except send passwords:

```sh
sudo systemd-run --pipe --wait --collect -p RuntimeMaxSec=60 \
     -p ImportCredential='lime.*' -p DynamicUser=yes -p StateDirectory=lime \
     /usr/local/bin/lime --dry-run /etc/lime/lime.toml
```

With your Macs booted, each should show up as the right Mac and as booted:

```
mymac (MacBook-Air on eth0, 10.23.1.151:22): booted (only keyboard-interactive offered). Next check in 900s
```

If a booted Mac shows "at the pre-boot unlock: would send the password" instead, or its connection is dropped, its drop-in (2b) isn't in effect: `sshd -T -C user=…` should show the three lines listed there. Other SSH servers on the network are listed once as "not one of the configured Macs".

#### d. Enable it

```sh
sudo systemctl daemon-reload
sudo systemctl enable --now lime
journalctl -u lime -f
```

### 4. Test it

Restart a Mac (`sudo shutdown -r now`) and watch the journal. Once the Mac reaches the pre-boot stage and announces itself, you should see:

```
mymac (MacBook-Air on eth0, 10.23.1.151:22): unlocked; macOS is starting. Next check in 900s
```

Expect a minute or two before the Mac is up. After a FileVault unlock, macOS stops at the login window: nobody is logged in.

## Running it

- **Each Mac's schedule** is kept in `/var/lib/lime/<name>`: when it may next be checked, and the wait after the next refusal. To have lime try a Mac again right away, run `sudo rm /var/lib/private/lime/<name>` and restart lime. A Mac whose SSH announcement disappears and comes back, as in a restart, is also tried again right away.
- **Adding a Mac:** sections 2a–2c on the Mac, then its `[[mac]]` entry, its `lime.<name>` credential, and `sudo systemctl restart lime`.
- **Changing a password:** re-run 3a for that Mac and restart lime.
- **Log priorities:**
  - notice for unlocks and booted Macs;
  - warning for refused passwords, misconfigured Macs, unreachable servers, and faults.

## Limitations

- **Verified against emulated Macs and the real OS's behaviour.** Discovery (systemd-resolved's Varlink mDNS), host-key identification, and all three verdicts — booted, pre-boot refusal, and unlock (the "System successfully unlocked." banner, and a clean close or a hang after the password) — have been driven end to end against emulated Macs on a two-host virtual network, with the systemd sandbox checked under systemd 259. The pre-boot unlock is an existing macOS procedure that works by hand on 26.6.1; lime automates it, with the server's behaviour pinned to Apple's `sshd-fvunlock`/`pam_basesystem` source and the 26.6.1 system image (see Sources).
- **The password reaches the booted Mac too.** lime sends it on every check to confirm the Mac is up. The account lands nowhere (2b), and the Mac is pinned by host key, so only root on that same booted Mac could capture it, and they already have the decrypted disk.
- **A wrong stored password costs attempts.** lime catches one while a Mac is booted and logs it as a warning. If a Mac is at pre-boot, each refused password uses up one of its attempts: macOS adds delays after a few wrong tries and requires Recovery after 10. lime retries on a doubling backoff. Update a changed password promptly (3a).
- lime doesn't log a user in after the unlock. Anything that needs a login session, such as menu-bar apps or user LaunchAgents, waits until someone logs in, for example over Screen Sharing.
- Every SSH server announced on the listed interfaces gets one handshake when it appears, so lime can learn which Mac it is.
- The pre-boot server always accepts password logins from the local network, whatever your `sshd_config` says. Keep the account password strong, and keep the Macs' network trusted.
- Root on the Linux host can decrypt the credentials. Any unattended unlocker has that property.

## Sources

What lime relies on about the pre-boot unlock, and where each fact comes from. Checked against macOS 26.6.1 (build 25G76); Apple's sources are the `apple-oss-distributions` mirrors.

- **The pre-boot SSH server is real and documented.** `OpenSSH`'s `sshd-keygen-wrapper/SSHDWrapper.swift` launches the BaseSystem sshd for FileVault unlock, and `apple_ssh_and_filevault.7` describes it. It runs as `sshd -i -oUsePAM=yes -oPamServiceName=sshd-basesystem -oAppleBaseSystem=yes` with host keys copied from the Preboot volume — **no `AuthenticationMethods` or `PasswordAuthentication` override**.
- **The pre-boot server presents the Mac's own host keys** (so pinning identifies it). On a normal boot, `sshd-keygen-wrapper` copies each host key from `/etc/ssh` on the Data volume to the Preboot volume at `…/<volumeGroupUUID>/var/db/sshd`; the Preboot volume is not FileVault-encrypted, so the keys are readable before unlock. At pre-boot the BaseSystem sshd is launched with `-oHostKey=` pointing there — the source comment: "use the host keys that were previously sync'd from the data volume." A key stored wrapped (`<name>.enc` + `<name>.refkey`) is unwrapped through the Secure Enclave (`AKSRefKey`) into `/tmp/ssh` first. (`OpenSSH`, `sshd-keygen-wrapper/SSHDWrapper.swift`.)
- **Pre-boot offers publickey, password and keyboard-interactive.** Confirmed from the 26.6.1 BaseSystem image (IPSW image `022-22048`, which holds `/usr/libexec/sshd-fvunlock`, `sshd-keygen-wrapper` and `/usr/share/pam.d/sshd-basesystem`): its `sshd_config` leaves every auth method at the OpenSSH default, and its only `sshd_config.d` drop-in, Apple's `100-macos.conf`, restricts nothing. Matches a live observation on a 26.6.1 Mac.
- **Our booted drop-in can't leak into pre-boot.** `/etc` → `/private/etc`, which lives on the FileVault-encrypted **Data volume**: on the sealed System volume it exists only as a seed template under `System/Library/Templates/Data/private/etc`. At pre-boot the Data volume is locked, so `50-lime-unlock.conf` is unreadable; the BaseSystem sshd reads its own `/etc`. The two environments never share a config.
- **"System successfully unlocked." is an SSH banner, not shell output.** `pam_modules`' `pam_basesystem.m` runs `/usr/libexec/sshd-fvunlock`, then sends that text with `pam_prompt(PAM_TEXT_INFO, …)` and calls `reboot3(RB3_PIVOTROOT)`. OpenSSH delivers a PAM text message as `SSH_MSG_USERAUTH_BANNER` during authentication (`auth2.c`), before `SSH_MSG_USERAUTH_SUCCESS` and before any channel or shell — so it cannot be a login shell or `ForceCommand` feed. lime reads it via russh's `auth_banner` callback.
- **A booted Mac just completes the login.** With the drop-in's `ForceCommand /usr/bin/false` and `DisableForwarding`, authentication succeeds and the account can do nothing; lime disconnects without opening a session. Verified against OpenSSH 10 in a container, along with the method-set difference and the close/hang after a pre-boot unlock.
- **A FileVault SSH unlock logs nobody in.** `sshd-fvunlock` pivots into macOS, which boots to the login window; lime doesn't need `DisableFDEAutoLogin`.
