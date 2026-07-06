# Kerbtool

## Description
Kerbtool is designed to do a variety of Kerberos related tasks from Linux
such as to request, forge and inspect Kerberos tickets, and to convert
between the CCache and Kirbi ticket cache formats.

Kerbtool is built on top of my fork of the library [gokrb5](https://github.com/jfjallid/gokrb5),
originally created by jcmturner but modified to support the use cases for this
tool.

In scenarios where requesting tickets cross Kerberos realms it might help to
specify the fqdn of the domain controller, a dns server and possibly a krb5.conf
which specifies the KDC to contact for every domain along the way.

In scenarios where tickets are requested via a SOCKS proxy, DNS traffic is
forced to use TCP, but it is also recommended to specify a dns server to use.

### NETBIOS vs DNS realm handling

Active Directory tickets are sometimes issued (or stored in ccache files) with
the realm set to the **NETBIOS** form of the domain (e.g. `CONTOSO`) rather
than the **DNS** form (e.g. `CONTOSO.LOCAL`). Kerberos in general — and gokrb5
in particular — treats realm strings as opaque, so a ticket whose realm is
`CONTOSO` is not interchangeable with one whose realm is `CONTOSO.LOCAL`
without explicit help.

To make this more seamless, kerbtool does two things automatically:

1. **Permissive realm comparison.** When deciding whether a loaded ccache
   matches `--domain`, kerbtool treats the first DNS label of one form as the
   NETBIOS form of the other (so `CONTOSO` ≈ `CONTOSO.LOCAL`).
2. **NETBIOS realm alias in the generated krb5 config.** Unless you supply
   `--krb5-conf`, kerbtool registers an additional realm pointing at the same
   KDC under the NETBIOS form, plus a `[domain_realm]` mapping for the DNS
   domain, so cross-realm referral resolution works either way.

> **⚠️ This is a permissive heuristic and can be wrong.**
> The default NETBIOS form is derived as *the first DNS label of `--domain`,
> uppercased*. This holds for the vast majority of AD environments but is
> not guaranteed by the protocol — NETBIOS names can be truncated, renamed,
> or completely unrelated to the DNS domain. In such environments
> `realmsMatch()` may return `true` for two realms that are actually
> distinct, and the auto-registered alias may point at the wrong KDC.
>
> If you hit this case, pass `--netbios-domain <NAME>` to override the
> default derivation, or supply your own `--krb5-conf` to take full control
> of realm/KDC mapping. The flag does not disable the permissive comparison;
> it only changes which NETBIOS name is treated as canonical.

## Credits
This project had not been possible without the Kerberos library written by [jcmturner](https://github.com/jcmturner/gokrb5).

Much of the code has been inspired by Impacket's getST.py, getTGT.py,
ticketConverter.py, GetUserSPNs.py, GetNPUsers.py, and ticketer.py.

## Contributions
Issues and/or pull requests regarding problems or new features are welcome!

## Usage
```
Usage: kerbtool <service> [options]

<service>:
      --ask-tgt             Request a TGT from the KDC
      --ask-st              Request a Service Ticket from the TGS
      --forge               Craft a TGT or ST using an AES or NT Hash
      --parse               Decrypt and inspect a provided ticket
      --convert             Convert between CCACHE and KIRBI formats
      --kerberoast          Kerberoast specific account based on SPN
      --asreproast          AS-REP roast specific account that does not require pre-auth
      --set-password        Change your own or reset another account's password (kpasswd)
      --keytab              Create, read, and modify keytab files
  
General options:
  -P, --port <port>           Kerberos Port (default 88)
  -d, --domain <domain>       Domain name to use for login
      --netbios-domain <name> Explicit NETBIOS form of --domain (defaults to the first DNS label
                              of --domain, uppercased). Permissive heuristic — see README note.
  -u, --user <username>       Username
  -p, --pass <pass>           Password
      --hash <NT Hash>        Hex encoded NT Hash for user password
  -n, --no-pass               Do not prompt for password
      --dc <fqdn/ip>          Optionally specify fqdn or ip of KDC when requesting tickets
      --aes-key <AES key>     Use a hex encoded AES128/256 key for Kerberos authentication
      --sha2                  (experimental) Use SHA256 and SHA384 for provided AES key
      --pfx <file>            Path to PFX/P12 certificate file for PKINIT authentication
      --pfx-pass <pass>       Password for the PFX file (prompts if omitted; pass "" for an empty password)
      --keytab-file <file>    Authenticate using keys from an existing keytab file
      --socks-host <target>   Establish connection via a SOCKS5 proxy server
      --socks-port <port>     SOCKS5 proxy port (default 1080)
      --dns-host <ip:port>    Override system's default DNS resolver
      --dns-tcp               Force DNS lookups over TCP. Default true when using --socks-host
  -t, --timeout               Dial timeout in seconds (default 5)

      --debug                 Enable debug logging
      --verbose               Enable verbose logging
  -q, --quiet                 Reduce amount of output
  -v, --version               Show version

```

### AskTGT specific usage
```
Usage: kerbtool --ask-tgt [options]

General options:
  -P, --port <port>           Kerberos Port (default 88)
  -d, --domain <domain>       Domain name to use for login
      --netbios-domain <name> Explicit NETBIOS form of --domain (defaults to the first DNS label
                              of --domain, uppercased). Permissive heuristic — see README note.
  -u, --user <username>       Username
  -p, --pass <pass>           Password
      --hash <NT Hash>        Hex encoded NT Hash for user password
  -n, --no-pass               Do not prompt for password
      --dc <fqdn/ip>          Optionally specify fqdn or ip of KDC when requesting tickets
      --aes-key <AES key>     Use a hex encoded AES128/256 key for Kerberos authentication
      --sha2                  (experimental) Use SHA256 and SHA384 for provided AES key
      --pfx <file>            Path to PFX/P12 certificate file for PKINIT authentication
      --pfx-pass <pass>       Password for the PFX file (prompts if omitted; pass "" for an empty password)
      --keytab-file <file>    Authenticate using keys from an existing keytab file
      --socks-host <target>   Establish connection via a SOCKS5 proxy server
      --socks-port <port>     SOCKS5 proxy port (default 1080)
      --dns-host <ip:port>    Override system's default DNS resolver
      --dns-tcp               Force DNS lookups over TCP. Default true when using --socks-host
  -t, --timeout               Dial timeout in seconds (default 5)

      --debug                 Enable debug logging
      --verbose               Enable verbose logging
  -q, --quiet                 Reduce amount of output
  -v, --version               Show version


options:
      --sign-nt <NT Hash>     Hex encoded NT Hash of key to sign or decrypt ticket with
      --sign-aes <AES key>    Hex encoded AES128/256 key to sign or decrypt ticket with
      --dump-all              Write all tickets to the CCache file
      --out-file <path>       Filename to write requested/forged ticket to (default creds.ccache)
      --inspect               Inspect content of requested, forged or parsed ticket. Requires --sign-nt or --sign-aes
      --request-rc4           Ask for RC4 encrypted encPart of KDC REP, not the actual ticket (default false)
      --krb5-conf <file>      Read krb5.conf file and use as config

```

### AskST specific usage
```
Usage: kerbtool --ask-st [options]

General options:
  -P, --port <port>           Kerberos Port (default 88)
  -d, --domain <domain>       Domain name to use for login
      --netbios-domain <name> Explicit NETBIOS form of --domain (defaults to the first DNS label
                              of --domain, uppercased). Permissive heuristic — see README note.
  -u, --user <username>       Username
  -p, --pass <pass>           Password
      --hash <NT Hash>        Hex encoded NT Hash for user password
  -n, --no-pass               Do not prompt for password
      --dc <fqdn/ip>          Optionally specify fqdn or ip of KDC when requesting tickets
      --aes-key <AES key>     Use a hex encoded AES128/256 key for Kerberos authentication
      --sha2                  (experimental) Use SHA256 and SHA384 for provided AES key
      --pfx <file>            Path to PFX/P12 certificate file for PKINIT authentication
      --pfx-pass <pass>       Password for the PFX file (prompts if omitted; pass "" for an empty password)
      --keytab-file <file>    Authenticate using keys from an existing keytab file
      --socks-host <target>   Establish connection via a SOCKS5 proxy server
      --socks-port <port>     SOCKS5 proxy port (default 1080)
      --dns-host <ip:port>    Override system's default DNS resolver
      --dns-tcp               Force DNS lookups over TCP. Default true when using --socks-host
  -t, --timeout               Dial timeout in seconds (default 5)

      --debug                 Enable debug logging
      --verbose               Enable verbose logging
  -q, --quiet                 Reduce amount of output
  -v, --version               Show version


options:
      --spn <SPN>             SPN used to request or forge a service ticket of format "service/FQDN"
      --sign-nt <NT Hash>     Hex encoded NT Hash of key to sign or decrypt ticket with
      --sign-aes <AES key>    Hex encoded AES128/256 key to sign or decrypt ticket with
      --impersonate <user>    Impersonate target username through S4U. Requires delegation to be setup
      --dump-all              Write all tickets to the CCache file
      --ccache-file <path>    Filename to write requested ticket to (default creds.ccache)
      --inspect               Inspect content of requested, forged or parsed ticket. Requires --sign-nt or --sign-aes
      --request-rc4           Ask for RC4 encrypted encPart of KDC REP, not the actual ticket (default false)
      --alt-service <SPN>     Override sname/SPN in ticket. Works if both services share account password.
      --krb5-conf <file>      Read krb5.conf file and use as config

```

### TicketForger specific usage
```
Usage: kerbtool --forge [options]

General options:
  -P, --port <port>           Kerberos Port (default 88)
  -d, --domain <domain>       Domain name to use for login
      --netbios-domain <name> Explicit NETBIOS form of --domain (defaults to the first DNS label
                              of --domain, uppercased). Permissive heuristic — see README note.
  -u, --user <username>       Username
  -p, --pass <pass>           Password
      --hash <NT Hash>        Hex encoded NT Hash for user password
  -n, --no-pass               Do not prompt for password
      --dc <fqdn/ip>          Optionally specify fqdn or ip of KDC when requesting tickets
      --aes-key <AES key>     Use a hex encoded AES128/256 key for Kerberos authentication
      --sha2                  (experimental) Use SHA256 and SHA384 for provided AES key
      --pfx <file>            Path to PFX/P12 certificate file for PKINIT authentication
      --pfx-pass <pass>       Password for the PFX file (prompts if omitted; pass "" for an empty password)
      --keytab-file <file>    Authenticate using keys from an existing keytab file
      --socks-host <target>   Establish connection via a SOCKS5 proxy server
      --socks-port <port>     SOCKS5 proxy port (default 1080)
      --dns-host <ip:port>    Override system's default DNS resolver
      --dns-tcp               Force DNS lookups over TCP. Default true when using --socks-host
  -t, --timeout               Dial timeout in seconds (default 5)

      --debug                 Enable debug logging
      --verbose               Enable verbose logging
  -q, --quiet                 Reduce amount of output
  -v, --version               Show version


options:
      --target  <username>    Username to put in forged or modified ticket
      --user-rid <RID>        Relative id of --target user
      --domain-sid <SID>      SID of domain to use in forged ticket
      --extra-sids <SID>,..   List of Sids to put in extra sids field of forged ticket
      --groups  <RID>,..      List of group relative ids to put in forged ticket (default 513,512,520,518,519)
      --spn <SPN>             SPN used to forge a service ticket of format "service/FQDN"
      --duration <duration>   Ticket validity duration for crafted tickets. Format 8h, 30m. (default 10h)
      --logon-server <name>   Logon server to populate forged ticket with
      --impersonate <user>    Create a Sapphire ticket, impersonating the specified user through Kerberos U2U
      --sign-nt <NT Hash>     Hex encoded NT Hash of key to sign or decrypt ticket with
      --sign-aes <AES key>    Hex encoded AES128/256 key to sign or decrypt ticket with
      --out-file <path>       Filename to write requested/forged ticket to (default creds.ccache)
      --inspect               Inspect content of forged ticket. Requires --sign-nt or --sign-aes
      --request-rc4           Ask for RC4 encrypted encPart of KDC REP, not the actual ticket (default false)
      --krb5-conf <file>      Read krb5.conf file and use as config
      --request               Request a TGT and modify it (Diamond ticket)
```

### TicketConverter specific usage
```
Usage: kerbtool --convert [options]
options:
      --in <file>             Path to ticket file to convert from CCACHE/Kirbi
      --out <file>            Path to save converted ticket file. Skip to get output as B64
      --ticket <b64>          B64 string of ticket to convert. Mutually exclusive with --in

      --debug                 Enable debug logging
      --verbose               Enable verbose logging
  -v, --version               Show version
```

### TicketParser specific usage
```
Usage: ./kerbtool --parse [options]

General options:
  -P, --port <port>           Kerberos Port (default 88)
  -d, --domain <domain>       Domain name to use for login
      --netbios-domain <name> Explicit NETBIOS form of --domain (defaults to the first DNS label
                              of --domain, uppercased). Permissive heuristic — see README note.
  -u, --user <username>       Username
  -p, --pass <pass>           Password
      --hash <NT Hash>        Hex encoded NT Hash for user password
  -n, --no-pass               Do not prompt for password
      --dc <fqdn/ip>          Optionally specify fqdn or ip of KDC when requesting tickets
      --aes-key <AES key>     Use a hex encoded AES128/256 key for Kerberos authentication
      --sha2                  (experimental) Use SHA256 and SHA384 for provided AES key
      --pfx <file>            Path to PFX/P12 certificate file for PKINIT authentication
      --pfx-pass <pass>       Password for the PFX file (prompts if omitted; pass "" for an empty password)
      --keytab-file <file>    Authenticate using keys from an existing keytab file
      --socks-host <target>   Establish connection via a SOCKS5 proxy server
      --socks-port <port>     SOCKS5 proxy port (default 1080)
      --dns-host <ip:port>    Override system's default DNS resolver
      --dns-tcp               Force DNS lookups over TCP. Default true when using --socks-host
  -t, --timeout               Dial timeout in seconds (default 5)

      --debug                 Enable debug logging
      --verbose               Enable verbose logging
  -q, --quiet                 Reduce amount of output
  -v, --version               Show version


options:
      --sign-nt <NT Hash>     Hex encoded NT Hash of key to decrypt ticket with
      --sign-aes <AES key>    Hex encoded AES128/256 key to decrypt ticket with
      --ticket <hex>          Hex encoded ticket bytes to inspect
      --in <file>             File with ticket in ccache or kirbi format
```

### Kerberoast specific usage
```
Usage: kerbtool --kerberoast [options]

General options:
  -P, --port <port>           Kerberos Port (default 88)
  -d, --domain <domain>       Domain name to use for login
      --netbios-domain <name> Explicit NETBIOS form of --domain (defaults to the first DNS label
                              of --domain, uppercased). Permissive heuristic — see README note.
  -u, --user <username>       Username
  -p, --pass <pass>           Password
      --hash <NT Hash>        Hex encoded NT Hash for user password
  -n, --no-pass               Do not prompt for password
      --dc <fqdn/ip>          Optionally specify fqdn or ip of KDC when requesting tickets
      --aes-key <AES key>     Use a hex encoded AES128/256 key for Kerberos authentication
      --sha2                  (experimental) Use SHA256 and SHA384 for provided AES key
      --pfx <file>            Path to PFX/P12 certificate file for PKINIT authentication
      --pfx-pass <pass>       Password for the PFX file (prompts if omitted; pass "" for an empty password)
      --keytab-file <file>    Authenticate using keys from an existing keytab file
      --socks-host <target>   Establish connection via a SOCKS5 proxy server
      --socks-port <port>     SOCKS5 proxy port (default 1080)
      --dns-host <ip:port>    Override system's default DNS resolver
      --dns-tcp               Force DNS lookups over TCP. Default true when using --socks-host
  -t, --timeout               Dial timeout in seconds (default 5)

      --debug                 Enable debug logging
      --verbose               Enable verbose logging
  -q, --quiet                 Reduce amount of output
  -v, --version               Show version


options:
      --target <SPN|SAN|UPN>  Target to kerberoast. Supports multiple formats such as service/fqdn, sAMAccountName and UPN."
      --name <username>       Target username for output hash (default user)
      --krb5-conf <file>      Read krb5.conf file and use as config
```
### AS Reproast specific usage
```
Usage: ./kerbtool --asreproast [options]

General options:
  -P, --port <port>           Kerberos Port (default 88)
  -d, --domain <domain>       Domain name to use for login
      --netbios-domain <name> Explicit NETBIOS form of --domain (defaults to the first DNS label
                              of --domain, uppercased). Permissive heuristic — see README note.
  -u, --user <username>       Username
  -p, --pass <pass>           Password
      --hash <NT Hash>        Hex encoded NT Hash for user password
  -n, --no-pass               Do not prompt for password
      --dc <fqdn/ip>          Optionally specify fqdn or ip of KDC when requesting tickets
      --aes-key <AES key>     Use a hex encoded AES128/256 key for Kerberos authentication
      --sha2                  (experimental) Use SHA256 and SHA384 for provided AES key
      --pfx <file>            Path to PFX/P12 certificate file for PKINIT authentication
      --pfx-pass <pass>       Password for the PFX file (prompts if omitted; pass "" for an empty password)
      --keytab-file <file>    Authenticate using keys from an existing keytab file
      --socks-host <target>   Establish connection via a SOCKS5 proxy server
      --socks-port <port>     SOCKS5 proxy port (default 1080)
      --dns-host <ip:port>    Override system's default DNS resolver
      --dns-tcp               Force DNS lookups over TCP. Default true when using --socks-host
  -t, --timeout               Dial timeout in seconds (default 5)

      --debug                 Enable debug logging
      --verbose               Enable verbose logging
  -q, --quiet                 Reduce amount of output
  -v, --version               Show version


options:
      --target <username>     Target user to AS-REP Roast. Supports multiple formats"
      --krb5-conf <file>      Read krb5.conf file and use as config
```

### SetPassword specific usage
```
Usage: ./kerbtool --set-password [options]

Change your own password or, with --target-user, reset another account's
password over the Kerberos kpasswd protocol (RFC 3244, port 464).

Without --target-user the authenticating account's own password is changed
(works even if the current password is expired). With --target-user the
authenticating account resets the named account's password and therefore
must hold reset privileges over it.

General options:
  -P, --port <port>           Kerberos Port (default 88)
  -d, --domain <domain>       Domain name to use for login
      --netbios-domain <name> Explicit NETBIOS form of --domain (defaults to the first DNS label
                              of --domain, uppercased). Permissive heuristic — see README note.
  -u, --user <username>       Username
  -p, --pass <pass>           Password
      --hash <NT Hash>        Hex encoded NT Hash for user password
  -n, --no-pass               Do not prompt for password
      --dc <fqdn/ip>          Optionally specify fqdn or ip of KDC when requesting tickets
      --aes-key <AES key>     Use a hex encoded AES128/256 key for Kerberos authentication
      --sha2                  (experimental) Use SHA256 and SHA384 for provided AES key
      --pfx <file>            Path to PFX/P12 certificate file for PKINIT authentication
      --pfx-pass <pass>       Password for the PFX file (prompts if omitted; pass "" for an empty password)
      --keytab-file <file>    Authenticate using keys from an existing keytab file
      --socks-host <target>   Establish connection via a SOCKS5 proxy server
      --socks-port <port>     SOCKS5 proxy port (default 1080)
      --dns-host <ip:port>    Override system's default DNS resolver
      --dns-tcp               Force DNS lookups over TCP. Default true when using --socks-host
  -t, --timeout               Dial timeout in seconds (default 5)

      --debug                 Enable debug logging
      --verbose               Enable verbose logging
  -q, --quiet                 Reduce amount of output
  -v, --version               Show version


options:
      --new-pass <password>   New password to set. Prompted for (with confirmation) if omitted.
      --target-user <name>    Account to reset. Omit to change your own password.
      --krb5-conf <file>      Read krb5.conf file and use as config
```

### Keytab specific usage
```
Usage: ./kerbtool --keytab [options]

Operations (choose one; --list is the default):
      --create                Create a new empty keytab (refuses to overwrite --file)
      --list                  List the entries in the keytab
      --add                   Add entries from the provided key material
      --remove                Remove entries matching --principal/--realm
      --replace               Remove matching entries for the principal, then add new ones
      --update-kvno           Set the kvno of matching entries to --kvno

options:
      --file <path>           Keytab file to operate on (required)
      --principal <name>      Principal, e.g. host/srv.dom.com or Administrator
      --realm <REALM>         Realm for the principal (uppercased)
      --salt <salt>           Override the salt used for --kt-pass derivation
                              (default is the realm+principal derivation)
      --kt-pass <password>    Derive key(s) from a password
      --kt-pass-hex <hex>     Derive key(s) from a UTF-16LE password blob given as hex,
                              e.g. an AD machine account password. RC4 uses MD4 of the
                              bytes; AES uses the UTF-8 form. Pair with --salt or
                              --query-salt for the correct (non-default) machine salt
      --kt-hash <hex>         NT hash (RC4 / etype 23) key
      --kt-aes128 <hex>       AES128 (etype 17) key
      --kt-aes256 <hex>       AES256 (etype 18) key
      --enctype <list>        Comma-separated enctypes to derive from --kt-pass (default
                              aes256-cts-hmac-sha1-96,aes128-cts-hmac-sha1-96,rc4-hmac);
                              for --remove/--update-kvno an optional single-enctype filter
      --kvno <n>              Key version number to assign (default 1)
      --match-kvno <n>        Only match entries with this kvno (remove/replace/update-kvno)
      --query-salt            Fetch the account salt from the KDC for --kt-pass derivation
                              (requires -d/--domain and KDC connectivity)

The connection options (-d/--domain, --dc, etc.) are only used by --query-salt,
which performs an unauthenticated AS-REQ to learn the account's real salt. All
other keytab operations are fully offline.
```

## AskTGT
Request a TGT using a password, NT Hash or AES key
```
/kerbtool --ask-tgt --user administrator --domain mydomain.local --pass <pass>
/kerbtool --ask-tgt --user administrator --domain mydomain.local --hash <NT Hash>
/kerbtool --ask-tgt --user administrator --domain mydomain.local --aes-key <AES128/256 hex>
```

Request a TGT via PKINIT using a PFX/P12 certificate. If `--pfx-pass` is
omitted, kerbtool securely prompts for the PFX password; pass `--pfx-pass ""`
explicitly to attempt an empty password without prompting:
```
/kerbtool --ask-tgt --user administrator --domain mydomain.local --pfx cert.pfx
/kerbtool --ask-tgt --user administrator --domain mydomain.local --pfx cert.pfx --pfx-pass ""
/kerbtool --ask-tgt --user administrator --domain mydomain.local --pfx cert.pfx --pfx-pass <pass>
```

## AskST
Request a service ticket for a given SPN using password, NT Hash, AES key or a
CCache file with a TGT for the user when the environment variable KRB5CCNAME
is set:
```
./kerbtool --ask-st --user administrator --domain mydomain.local --pass <pass> --spn cifs/dc01.mydomain.local
./kerbtool --ask-st --user administrator --domain mydomain.local --hash <NT Hash> --spn cifs/dc01.mydomain.local
./kerbtool --ask-st --user administrator --domain mydomain.local --aes-key <AES128/256 hex> --spn cifs/dc01.mydomain.local
./kerbtool --ask-st --user administrator --domain mydomain.local --no-pass --spn cifs/dc01.mydomain.local
```

Override the service name/SPN using the `--alt-service` parameter when both
services are running from the same account.

Impersonate another user via S4U2Self and S4U2Proxy when abusing delegation
with the `--impersonate <username>` parameter.

## Forge tickets
Currently forging of Silver tickets, Golden tickets and Sapphire tickets are supported.

Forge a golden ticket using the krbtgt aes key:
```
./kerbtool --forge --target Administrator --domain mydomain.local --sign-aes <krbtgt AES key> --domain-sid <S-1-5-21-...>
```

Forge a silver ticket using the service account NT hash or AES key to impersonate the Administrator account:
```
./kerbtool --forge --target Administrator --domain mydomain.local --sign-nt <NT Hash> --domain-sid <S-1-5-21-...> --spn cifs/srv01.mydomain.local
./kerbtool --forge --target Administrator --domain mydomain.local --sign-aes <AES key> --domain-sid <S-1-5-21-...> --spn cifs/srv01.mydomain.local
```

Forge a sapphire ticket to impersonate the Administrator account:
```
./kerbtool --forge --user test --pass <pass> --domain mydomain.local --sign-aes <krbtgt AES key> --domain-sid <S-1-5-21-...> --request --impersonate Administrator
```

## Convert tickets
Convert from CCache to Kirbi and the other way around.
Input and output can be either files on disk or base64 encoded strings as argument and output.

```
./kerbtool --convert --in administrator.ccache --out administrator.kirbi
./kerbtool --convert --in administrator.kirbi --out administrator.ccache
./kerbtool --convert --in administrator.ccache
./kerbtool --convert --ticket BQQADAABAAj/////AAAAAAA... --out administrator.kirbi
./kerbtool --convert --ticket BQQADAABAAj/////AAAAAAA...
```

## Inspect tickets
To inspect a ticket, either provide a ticket from disk in ccache or kirbi
format, or provide a hex encoded ticket as seen in Wireshark.
The signing key argument should be same as was used to create the ticket.
Typically AES256 for realm local ticket and NT Hash for referral tickets.
```
./kerbtool --parse --in administrator.ccache --sign-aes <krbtgt AES256 key> 
```

The output would look something like this:
```
Decrypting ticket with a keytype: 18, key: d7e3794...35
Ticket content:
TktVNO: 5
Realm: MYDOMAIN.LOCAL
SName: (type: 2, name: krbtgt/MYDOMAIN.LOCAL)
Ticket encrypted part:
  Flags: [Forwardable Renewable Initial PreAuthent EncPARep Canonicalize]
  CRealm: MYDOMAIN.LOCAL
  CName: administrator
  CName: (type: 1, name: administrator)
  AuthTime: 2025-06-07 15:54:49 +0000 UTC
  StartTime: 2025-06-07 15:54:49 +0000 UTC
  EndTime: 2025-06-08 01:54:48 +0000 UTC
  RenewTill: 2025-06-09 15:54:48 +0000 UTC
  CAddr: []
  AuthorizationData:
  AuthorizationData[0].ADType: ADIfRelevant
  AuthorizationData[0].ADData[0].ADType: ADWin2KPAC
### PAC ###
PAC.CBuffers: 5
PAC.Version: 0

### KerbValidationInfo ###
LogOnTime: 2025-06-07 15:54:49.5488861 +0000 UTC
LogOffTime: 2185-07-21 23:34:33.709551516 +0000 UTC
KickOffTime: 2185-07-21 23:34:33.709551516 +0000 UTC
PasswordLastSet: 2025-06-07 11:06:16.5506286 +0000 UTC
PasswordCanChange: 2025-06-08 11:06:16.5506286 +0000 UTC
PasswordMustChange: 2185-07-21 23:34:33.709551516 +0000 UTC
EffectiveName: Administrator
FullName: 
LogonScript: 
ProfilePath: 
HomeDirectory: 
HomeDirectoryDrive: 
LogonCount: 32
BadPasswordCount: 0
UserID: 500
PrimaryGroupID: 513
GroupCount: 6
GroupIDs: [{RelativeID:1108 Attributes:7} {RelativeID:513 Attributes:7} {RelativeID:512 Attributes:7} {RelativeID:520 Attributes:7} {RelativeID:518 Attributes:7} {RelativeID:519 Attributes:7}]
UserFlags: 32
UserSessionKey: {CypherBlock:[{Data:[0 0 0 0 0 0 0 0]} {Data:[0 0 0 0 0 0 0 0]}]}
LogonServer: DC01
LogonDomainName: MYDOMAIN
LogonDomainID: {Revision:1 SubAuthorityCount:4 IdentifierAuthority:[0 0 0 0 0 5] SubAuthority:[21 3301781224 2943037444 2400903060]}
UserAccountControl: 528
SubAuthStatus: 0
LastSuccessfulILogon: 2185-07-21 23:34:33.709551616 +0000 UTC
LastFailedILogon: 2185-07-21 23:34:33.709551616 +0000 UTC
FailedILogonCount: 0
SIDCount: 1
ExtraSIDs: [{SID:{Revision:1 SubAuthorityCount:1 IdentifierAuthority:[0 0 0 0 0 18] SubAuthority:[1]} Attributes:7}]
ResourceGroupDomainSID: {Revision:0 SubAuthorityCount:0 IdentifierAuthority:[0 0 0 0 0 0] SubAuthority:[]}
ResourceGroupCount: 0
ResourceGroupIDs: []

### ClientInfo ###
ClientID: 2025-06-07 15:54:49 +0000 UTC
NameLength: 26
Name: administrator

### ClientClaims ###
<nil>

### ServerChecksum ###
SignatureType: 16
Signature: 3f22c1ae418fcb841ba85270
RODCIdentifier: 0

### KDCChecksum ###
SignatureType: 16
Signature: afd832fa107281815ed8c624
RODCIdentifier: 0

### UPNDNSInfo ###
&{UPNLength:58 UPNOffset:16 DNSDomainNameLength:30 DNSDomainNameOffset:80 Flags:1 SamNameLength:0 SamNameOffset:0 SidLength:0 SidOffset:0 UPN:Administrator@mydomain.local DNSDomain:MYDOMAIN.LOCAL SamName: Sid:<nil>}

### PacAttributesInfo ###
<nil>

### PacRequestorSid ###
<nil>

### CredentialsInfo ###
<nil>

### S4UDelegationInfo ###
<nil>

### DeviceInfo ###
<nil>

### DeviceClaimsInfo ###
<nil>

```
## Kerberoast
Limited support for  Kerberoasting as there is no LDAP support to figure out which accounts can be targeted.
Currently it is supported to target a single user to request a service ticket and extract the hash for cracking.
Multiple formats for the username are supported according to principal name type NT-ENTERPRISE:
```
./kerbtool --kerberoast -u Administrator -d mydomain.local --target malcolm
```
```
./kerbtool --kerberoast -u Administrator -d mydomain.local --target malcolm@mydomain.local
```
```
./kerbtool --kerberoast -u Administrator -d mydomain.local --target mydomain\\malcolm
```

## AS-Rep roast
Limited support for AS-REP roasting as there is no LDAP support to figure out which accounts can be targeted.
Currently it is supported to target a single user to request a TGT and extract the hash for cracking.
Multiple formats for the username are supported according to principal name type NT-ENTERPRISE:
```
./kerbtool --asreproast -d mydomain.local --target tpol
```
```
./kerbtool --asreproast -d mydomain.local --target tpol@mydomain.local
```
```
./kerbtool --asreproast -d mydomain.local --target mydomain\\tpol
```

## Set password
Change a password over the Kerberos kpasswd protocol (RFC 3244, port 464).
Without `--target-user` the authenticating account's own password is changed,
which works even when the current password has expired. Authentication accepts
the usual credential forms (password, NT hash, AES key, PFX or keytab). The new
password is prompted for (with confirmation) when `--new-pass` is omitted.

Change your own password:
```
./kerbtool --set-password -u administrator -d mydomain.local --pass <current pass> --new-pass <new pass>
```

Reset another account's password (requires reset privileges over the target):
```
./kerbtool --set-password -u administrator -d mydomain.local --pass <pass> --target-user malcolm --new-pass <new pass>
```

## Keytab management
Create, inspect and modify keytab files offline. `--list` is the default
operation; `--create`, `--add`, `--remove`, `--replace` and `--update-kvno`
select the others. Key material can be supplied directly (`--kt-hash`,
`--kt-aes128`, `--kt-aes256`) or derived from a password (`--kt-pass`, or
`--kt-pass-hex` for a UTF-16LE machine account password blob).

> **⚠️ Salt note.** Password-derived AES keys depend on the salt. The default
> `realm+principal` derivation is correct for user accounts but **not** for
> machine accounts, whose salt is host-specific. For machine accounts pass the
> real salt with `--salt`, or let kerbtool fetch it from the KDC with
> `--query-salt` (the only keytab sub-mode that touches the network).

List the contents of a keytab:
```
./kerbtool --keytab --file service.keytab --list
```

Create a keytab with keys derived from a password (default enctype set):
```
./kerbtool --keytab --create --principal host/srv.mydomain.local --realm mydomain.local --kt-pass <pass>
```

Add a raw AES256 key (and an NT hash) for a principal to an existing keytab:
```
./kerbtool --keytab --file service.keytab --add --principal MSSQLSvc/db01.mydomain.local --realm mydomain.local --kt-aes256 <64 hex> --kt-hash <32 hex>
```

Derive a machine account's keys using the KDC-provided salt:
```
./kerbtool --keytab --create --principal host/srv.mydomain.local --realm mydomain.local --kt-pass-hex <UTF-16LE hex> --query-salt -d mydomain.local
```

Remove entries for a principal, or bump their kvno:
```
./kerbtool --keytab --file service.keytab --remove --principal MSSQLSvc/db01.mydomain.local --realm mydomain.local
./kerbtool --keytab --file service.keytab --update-kvno --principal host/srv.mydomain.local --realm mydomain.local --kvno 5
```
