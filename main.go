// MIT License
//
// # Copyright (c) 2025 Jimmy Fjällid
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
package main

import (
	"bytes"
	"encoding/hex"
	"flag"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	rundebug "runtime/debug"

	"golang.org/x/net/proxy"
	"golang.org/x/term"

	"github.com/jfjallid/go-smb/msdtyp"
	"github.com/jfjallid/golog"

	"github.com/jfjallid/gokrb5/v9/client"
	"github.com/jfjallid/gokrb5/v9/config"
	"github.com/jfjallid/gokrb5/v9/credentials"
	"github.com/jfjallid/gokrb5/v9/types"

	"github.com/jfjallid/gokrb5/v9/iana/etypeID"
	"github.com/jfjallid/gokrb5/v9/iana/flags"
	"github.com/jfjallid/gokrb5/v9/iana/nametype"

	"github.com/jfjallid/gokrb5/v9/messages"
	"github.com/jfjallid/mstypes"
)

var log = golog.Get("")
var release string = "0.2.1"
var myFlags *flag.FlagSet

var helpMsg = `
    Usage: ` + os.Args[0] + ` <service> [options]

    <service>:
          --ask-tgt             Request a TGT from the KDC
          --ask-st              Request a Service Ticket from the TGS
          --forge               Craft a TGT or ST using an AES or NT Hash
          --parse               Decrypt and inspect a provided ticket
          --convert             Convert between CCACHE and KIRBI formats
          --kerberoast          Kerberoast specific account based on SPN
          --asreproast          AS-REP roast specific account that does not require pre-auth
      ` + helpConnectionOptions + `
`
var helpGeneralOptions = `
          --debug                 Enable debug logging
          --verbose               Enable verbose logging
      -q, --quiet                 Reduce amount of output
      -v, --version               Show version
`
var helpConnectionOptions = `
    General options:
      -P, --port <port>           Kerberos Port (default 88)
      -d, --domain <domain>       Domain name to use for login
          --netbios-domain <name> Explicit NETBIOS form of --domain (defaults to the first DNS label
                                  of --domain, uppercased). Use only when the NETBIOS name is not the
                                  first label of the DNS domain (truncated/renamed/legacy environments).
      -u, --user <username>       Username
      -p, --pass <pass>           Password
          --hash <NT Hash>        Hex encoded NT Hash for user password
      -n, --no-pass               Do not prompt for password
          --dc <fqdn/ip>          Optionally specify fqdn or ip of KDC when requesting tickets
          --aes-key <AES key>     Use a hex encoded AES128/256 key for Kerberos authentication
          --sha2                  (experimental) Use SHA256 and SHA384 for provided AES key
          --pfx <file>            Path to PFX/P12 certificate file for PKINIT authentication
          --pfx-pass <pass>       Password for the PFX file (default: empty)
          --socks-host <target>   Establish connection via a SOCKS5 proxy server
          --socks-port <port>     SOCKS5 proxy port (default 1080)
          --dns-host <ip:port>    Override system's default DNS resolver 
          --dns-tcp               Force DNS lookups over TCP. Default true when using --socks-host
      -t, --timeout               Dial timeout in seconds (default 5)
	  ` + helpGeneralOptions + `
`

// Custom types to help with argument parsing and validation
type ridList []uint32
type stringList []string
type SID struct {
	s string
	v *msdtyp.SID
}
type SIDS []SID

type binaryArg []byte

func (n *ridList) String() string {
	return fmt.Sprintf("%v", *n)
}

func (n *ridList) Set(value string) error {
	parts := strings.Split(value, ",")
	for _, str := range parts {
		str = strings.TrimSpace(str)
		if strings.Contains(str, " ") {
			return fmt.Errorf("Rids should be separated by comma, not by space.")
		}
		if str != "" {
			v, err := strconv.ParseUint(str, 10, 32)
			if err != nil {
				return err
			}
			*n = append(*n, uint32(v))
		}
	}

	return nil
}

func (n *stringList) String() string {
	return fmt.Sprintf("%v", *n)
}

func (n *stringList) Set(value string) error {
	parts := strings.Split(value, ",")
	for _, str := range parts {
		str = strings.TrimSpace(str)
		if strings.Contains(str, " ") {
			return fmt.Errorf("List of strings should be separated by comma, not by space.")
		}
		if str != "" {
			*n = append(*n, str)
		}
	}

	return nil
}

func (n *SID) String() string {
	return n.s
}

func (n *SID) Set(value string) error {
	// Check if valid SID
	sid, err := msdtyp.ConvertStrToSID(value)
	n.s = value
	n.v = sid
	return err
}

func (n *SID) Get() *msdtyp.SID {
	return n.v
}

func (n *SID) GetRPCSID() mstypes.RPCSID {
	rpcsid := mstypes.RPCSID{
		Revision:          n.v.Revision,
		SubAuthorityCount: n.v.NumAuth,
		SubAuthority:      n.v.SubAuthorities,
	}
	copy(rpcsid.IdentifierAuthority[:], n.v.Authority[:6])
	return rpcsid
}

func (n *SIDS) String() string {
	return fmt.Sprintf("%v", *n)
}

func (n *SIDS) Set(value string) error {
	parts := strings.Split(value, ",")
	for i, _ := range parts {
		str := strings.TrimSpace(parts[i])
		if strings.Contains(str, " ") {
			return fmt.Errorf("SIDs should be separated by comma, not by space.")
		}
		if str != "" {
			sid, err := msdtyp.ConvertStrToSID(str)
			if err != nil {
				return fmt.Errorf("Failed to parse ExtraSid with error: %s\n", err)
			}
			*n = append(*n, SID{s: str, v: sid})
		}
	}

	return nil
}

func (n *binaryArg) String() string {
	return hex.EncodeToString(*n)
}

func (n *binaryArg) Set(value string) error {
	value = strings.TrimPrefix(value, "0x")
	val, err := hex.DecodeString(value)
	if err != nil {
		return fmt.Errorf("Invalid hex string for argument")
	}
	*n = val
	return nil
}

func isFlagSet(name string) bool {
	found := false
	myFlags.Visit(func(f *flag.Flag) {
		if f.Name == name {
			found = true
		}
	})
	return found
}

func printVersion() {
	fmt.Printf("Version: %s\n", release)
	bi, ok := rundebug.ReadBuildInfo()
	if !ok {
		log.Errorln("Failed to read build info to locate version imported modules")
	}
	for _, m := range bi.Deps {
		fmt.Printf("Package: %s, Version: %s\n", m.Path, m.Version)
	}
	return
}

type connArgs struct {
	username   string
	password   string
	hash       binaryArg
	userDomain string
	// netbiosDomain is the optional NETBIOS form of userDomain (e.g. "CONTOSO" when
	// userDomain is "contoso.local"). Used to tolerate ccaches/TGTs that carry the
	// NETBIOS form as the realm, and to register a NETBIOS realm alias in the
	// generated krb5 config. See normalizeDomains() for default-derivation and
	// realmsMatch() for the permissive comparison this enables.
	netbiosDomain      string
	netbiosDomainUpper string
	socksHost  string
	dcIP       string
	dc         string // Hostname or ip
	dcHost     string
	dcDomain   string
	aesKey     binaryArg
	sha2       bool
	pfxFile    string
	pfxPass    string
	dnsHost    string
	port       int
	timeout    time.Duration
	socksPort  int
	kerberos   bool
	dnsTCP     bool
	noPass     bool
	// Non-user arguments
	krbConf *config.Config
	c       *client.Client
	cache   *credentials.CCache
}

type generalArgs struct {
	debug      bool
	version    bool
	verbose    bool
	quiet      bool
	askTGT     bool
	askST      bool
	forge      bool
	parse      bool
	convert    bool
	kerberoast bool
	asRepRoast bool
}

type userArgs struct {
	connArgs
	generalArgs
	targetUsername string
	userRid        uint64
	signKeyNT      binaryArg
	signKeyAES     binaryArg
	domainSid      SID
	extraSids      SIDS
	groups         ridList
	logonServer    string
	spn            string
	ticketDuration time.Duration
	inspect        bool
	targetFile     string // CCACHE file to use for output
	requestRC4     bool
	dnsHost        string
	dnsTCP         bool
	krb5ConfFile   string
	request        bool
	impersonate    string
	ticketBytes    binaryArg
	altService     string
	inputFilename  string
	outputFilename string
	ticketB64      string
	dumpAllTickets      bool
	targetRealm         string
	u2u                 bool
	additionalTicketFile string
	unpacHash           bool
	// Non-user arguments
	serviceDomain   string
	templateTicket  messages.Ticket
	referral        bool
	serviceFQDN     string
	service         string
	serviceHost     string
	serviceNameType int32 // KRB_NT_SRV_INST | KRB_NT_ENTERPRISE, derived from --spn / --target
	signingKey      []byte
	signAes128Key   bool
	signAes256Key   bool
	signAes         bool
	userDomainUpper string
	ccacheFile      string // KRB5CCACHE filename
	noLogin			bool // When we want to handle login manually
}

func addConnectionArgs(flagSet *flag.FlagSet, argv *userArgs) {
	flagSet.StringVar(&argv.username, "u", "", "")
	flagSet.StringVar(&argv.username, "user", "", "")
	flagSet.StringVar(&argv.password, "p", "", "")
	flagSet.StringVar(&argv.password, "pass", "", "")
	flagSet.Var(&argv.hash, "hash", "")
	flagSet.StringVar(&argv.userDomain, "d", "", "")
	flagSet.StringVar(&argv.userDomain, "domain", "", "")
	flagSet.StringVar(&argv.netbiosDomain, "netbios-domain", "", "")
	flagSet.IntVar(&argv.port, "P", 88, "")
	flagSet.IntVar(&argv.port, "port", 88, "")
	flagSet.BoolVar(&argv.debug, "debug", false, "")
	flagSet.BoolVar(&argv.verbose, "verbose", false, "")
	flagSet.DurationVar(&argv.timeout, "t", time.Second*5, "")
	flagSet.DurationVar(&argv.timeout, "timeout", time.Second*5, "")
	flagSet.StringVar(&argv.socksHost, "socks-host", "", "")
	flagSet.IntVar(&argv.socksPort, "socks-port", 1080, "")
	flagSet.BoolVar(&argv.kerberos, "k", false, "")
	flagSet.BoolVar(&argv.kerberos, "kerberos", false, "")
	flagSet.StringVar(&argv.dc, "dc", "", "")
	flagSet.Var(&argv.aesKey, "aes-key", "")
	flagSet.BoolVar(&argv.sha2, "sha2", false, "")
	flagSet.StringVar(&argv.pfxFile, "pfx", "", "")
	flagSet.StringVar(&argv.pfxPass, "pfx-pass", "", "")
	flagSet.StringVar(&argv.dnsHost, "dns-host", "", "")
	flagSet.BoolVar(&argv.dnsTCP, "dns-tcp", false, "")
	flagSet.BoolVar(&argv.noPass, "n", false, "")
	flagSet.BoolVar(&argv.noPass, "no-pass", false, "")
	flagSet.BoolVar(&argv.quiet, "quiet", false, "")
	flagSet.BoolVar(&argv.quiet, "q", false, "")
}

func addAskTGTArgs(flagSet *flag.FlagSet, argv *userArgs) {
	flagSet.Var(&argv.signKeyNT, "sign-nt", "")
	flagSet.Var(&argv.signKeyAES, "sign-aes", "")
	flagSet.DurationVar(&argv.ticketDuration, "duration", time.Hour*10, "")
	flagSet.BoolVar(&argv.inspect, "inspect", false, "")
	flagSet.StringVar(&argv.targetFile, "out-file", "creds.ccache", "")
	flagSet.BoolVar(&argv.requestRC4, "request-rc4", false, "")
	flagSet.BoolVar(&argv.dumpAllTickets, "dump-all", false, "")
	flagSet.StringVar(&argv.krb5ConfFile, "krb5-conf", "", "")
	flagSet.BoolVar(&argv.unpacHash, "unpack-hash", false, "")
}

func addAskSTArgs(flagSet *flag.FlagSet, argv *userArgs) {
	flagSet.Var(&argv.signKeyNT, "sign-nt", "")
	flagSet.Var(&argv.signKeyAES, "sign-aes", "")
	flagSet.StringVar(&argv.spn, "spn", "", "")
	flagSet.DurationVar(&argv.ticketDuration, "duration", time.Hour*10, "")
	flagSet.BoolVar(&argv.inspect, "inspect", false, "")
	flagSet.StringVar(&argv.targetFile, "out-file", "creds.ccache", "")
	flagSet.BoolVar(&argv.requestRC4, "request-rc4", false, "")
	flagSet.StringVar(&argv.krb5ConfFile, "krb5-conf", "", "")
	flagSet.StringVar(&argv.impersonate, "impersonate", "", "")
	flagSet.StringVar(&argv.altService, "alt-service", "", "")
	flagSet.BoolVar(&argv.dumpAllTickets, "dump-all", false, "")
	flagSet.StringVar(&argv.ticketB64, "ticket", "", "")
	flagSet.BoolVar(&argv.referral, "ask-referral", false, "")
	flagSet.StringVar(&argv.targetRealm, "target-realm", "", "")
	flagSet.BoolVar(&argv.u2u, "u2u", false, "")
	flagSet.StringVar(&argv.additionalTicketFile, "additional-ticket", "", "")
}

func addForgeArgs(flagSet *flag.FlagSet, argv *userArgs) {
	flagSet.StringVar(&argv.targetUsername, "target", "Administrator", "")
	flagSet.Uint64Var(&argv.userRid, "user-rid", 500, "")
	flagSet.Var(&argv.signKeyNT, "sign-nt", "")
	flagSet.Var(&argv.signKeyAES, "sign-aes", "")
	flagSet.Var(&argv.domainSid, "domain-sid", "")
	flagSet.Var(&argv.extraSids, "extra-sids", "")
	flagSet.Var(&argv.groups, "groups", "")
	flagSet.StringVar(&argv.logonServer, "logon-server", "", "")
	flagSet.StringVar(&argv.spn, "spn", "", "")
	flagSet.DurationVar(&argv.ticketDuration, "duration", time.Hour*10, "")
	flagSet.BoolVar(&argv.inspect, "inspect", false, "")
	flagSet.StringVar(&argv.targetFile, "out-file", "creds.ccache", "")
	flagSet.BoolVar(&argv.requestRC4, "request-rc4", false, "")
	flagSet.StringVar(&argv.krb5ConfFile, "krb5-conf", "", "")
	flagSet.BoolVar(&argv.request, "request", false, "")
	flagSet.StringVar(&argv.impersonate, "impersonate", "", "")
}

func addParseTicketArgs(flagSet *flag.FlagSet, argv *userArgs) {
	flagSet.Var(&argv.signKeyNT, "sign-nt", "")
	flagSet.Var(&argv.signKeyAES, "sign-aes", "")
	flagSet.Var(&argv.ticketBytes, "ticket", "")
	flagSet.StringVar(&argv.inputFilename, "in", "", "")
	flagSet.BoolVar(&argv.verbose, "verbose", false, "")
}

func addConvertTicketArgs(flagSet *flag.FlagSet, argv *userArgs) {
	flagSet.StringVar(&argv.inputFilename, "in", "", "")
	flagSet.StringVar(&argv.outputFilename, "out", "", "")
	flagSet.StringVar(&argv.ticketB64, "ticket", "", "")
}

func addKerberoastArgs(flagSet *flag.FlagSet, argv *userArgs) {
	flagSet.StringVar(&argv.spn, "target", "", "")
	flagSet.StringVar(&argv.krb5ConfFile, "krb5-conf", "", "")
	flagSet.StringVar(&argv.targetUsername, "name", "user", "")
}

func addASREProastArgs(flagSet *flag.FlagSet, argv *userArgs) {
	flagSet.StringVar(&argv.username, "target", "", "")
	flagSet.StringVar(&argv.krb5ConfFile, "krb5-conf", "", "")
}

func handleArgs() (action byte, argv *userArgs, err error) {
	myFlags = flag.NewFlagSet("", flag.ExitOnError)
	myFlags.Usage = func() {
		fmt.Println(helpMsg)
		os.Exit(0)
	}
	argv = &userArgs{}
	myFlags.BoolVar(&argv.askTGT, "ask-tgt", false, "")
	myFlags.BoolVar(&argv.askST, "ask-st", false, "")
	myFlags.BoolVar(&argv.forge, "forge", false, "")
	myFlags.BoolVar(&argv.parse, "parse", false, "")
	myFlags.BoolVar(&argv.convert, "convert", false, "")
	myFlags.BoolVar(&argv.kerberoast, "kerberoast", false, "")
	myFlags.BoolVar(&argv.asRepRoast, "asreproast", false, "")
	myFlags.BoolVar(&argv.version, "v", false, "")
	myFlags.BoolVar(&argv.version, "version", false, "")

	if len(os.Args) < 2 {
		myFlags.Usage()
	}

	// Parse only first argument
	err = myFlags.Parse(os.Args[1:2])
	if err != nil {
		log.Errorf("err: %s\n", err)
		return
	}
	if argv.version {
		return
	}

	numAction := 0
	if argv.askTGT {
		numAction++
	}
	if argv.askST {
		numAction++
	}
	if argv.forge {
		numAction++
	}
	if argv.parse {
		numAction++
	}
	if argv.convert {
		numAction++
	}
	if argv.kerberoast {
		numAction++
	}
	if argv.asRepRoast {
		numAction++
	}
	if numAction != 1 {
		fmt.Println("Must specify ONE action. No more, no less")
		myFlags.Usage()
	}
	if argv.askTGT {
		myFlags.Usage = func() {
			fmt.Println(helpAskTGTOptions)
			os.Exit(0)
		}
		addAskTGTArgs(myFlags, argv)
		action = 1
	} else if argv.askST {
		myFlags.Usage = func() {
			fmt.Println(helpAskSTOptions)
			os.Exit(0)
		}
		addAskSTArgs(myFlags, argv)
		action = 2
	} else if argv.forge {
		myFlags.Usage = func() {
			fmt.Println(helpForgeOptions)
			os.Exit(0)
		}
		addForgeArgs(myFlags, argv)
		action = 3
	} else if argv.parse {
		myFlags.Usage = func() {
			fmt.Println(helpParseTicketOptions)
			os.Exit(0)
		}
		addParseTicketArgs(myFlags, argv)
		action = 4
	} else if argv.convert {
		myFlags.Usage = func() {
			fmt.Println(helpConvertTicketOptions)
			os.Exit(0)
		}
		addConvertTicketArgs(myFlags, argv)
		action = 5
	} else if argv.kerberoast {
		myFlags.Usage = func() {
			fmt.Println(helpKerberoastOptions)
			os.Exit(0)
		}
		addKerberoastArgs(myFlags, argv)
		action = 6
	} else if argv.asRepRoast {
		myFlags.Usage = func() {
			fmt.Println(helpASRepRoastOptions)
			os.Exit(0)
		}
		addASREProastArgs(myFlags, argv)
		action = 7
	}

	if !argv.convert && !argv.parse {
		addConnectionArgs(myFlags, argv)
	}
	err = myFlags.Parse(os.Args[1:])
	if err != nil {
		log.Errorf("error: %s\n", err)
		return
	}

	return
}

// normalizeDomains fills in args.userDomainUpper / args.netbiosDomainUpper from
// args.userDomain / args.netbiosDomain. Must be called before krbConf is built
// (in main()) and before setupKRB5Client.
//
// The default NETBIOS form is derived as the first DNS label of --domain,
// uppercased. This is correct for the vast majority of AD deployments but is
// NOT guaranteed — the NETBIOS name can be truncated, renamed, or completely
// unrelated to the DNS domain. Pass --netbios-domain explicitly when the
// heuristic guesses wrong. See also realmsMatch() in this file.
func normalizeDomains(args *userArgs) {
	args.userDomainUpper = strings.ToUpper(args.userDomain)
	if args.netbiosDomain == "" && args.userDomain != "" {
		args.netbiosDomain = strings.SplitN(args.userDomain, ".", 2)[0]
	}
	args.netbiosDomainUpper = strings.ToUpper(args.netbiosDomain)
}

// parsedSPN decomposes an AD principal/SPN string into its components. The
// raw string is always preserved and is what gets sent to the KDC verbatim;
// the decomposed fields are only for derived purposes (filename templates,
// CCache lookup targets, realm hints).
//
// AD-canonical formats supported (https://learn.microsoft.com/en-us/windows/win32/ad/name-formats-for-unique-spns):
//
//	serviceClass/instance                       -> KRB_NT_SRV_INST
//	serviceClass/instance:port                  -> KRB_NT_SRV_INST
//	serviceClass/instance:port/serviceName      -> KRB_NT_SRV_INST (4-part)
//	user@dnsRealm                                -> KRB_NT_ENTERPRISE (UPN)
//	sAMAccountName  (incl. computer$ form)       -> KRB_NT_ENTERPRISE (bare)
//
// An empty component means "not present in the input". The parser does no
// validation: any string yields a parsedSPN — callers decide how strict to be.
type parsedSPN struct {
	raw      string
	service  string // serviceClass; "" for UPN / sAMAccountName
	host     string // instance host without :port or trailing /serviceName
	domain   string // DNS suffix of host; "" for single-label hosts and for sAMAccountName
	port     string // optional :port from the instance
	svcName  string // optional trailing /serviceName in 4-part SPNs
	upnRealm string // UPN @-suffix; "" for non-UPN inputs
	isUPN    bool
	isSAM    bool
	nameType int32 // KRB_NT_SRV_INST or KRB_NT_ENTERPRISE
}

// fqdnLike reproduces the legacy serviceFQDN value: the full instance portion
// (host + optional :port + optional /serviceName). Kept stable so existing
// output-filename templates keep producing the same names.
func (p parsedSPN) fqdnLike() string {
	if p.service == "" {
		return ""
	}
	if i := strings.Index(p.raw, "/"); i >= 0 {
		return p.raw[i+1:]
	}
	return ""
}

func parseSPN(spn string) parsedSPN {
	p := parsedSPN{raw: spn, nameType: nametype.KRB_NT_ENTERPRISE}
	if i := strings.Index(spn, "/"); i >= 0 {
		p.service = spn[:i]
		p.nameType = nametype.KRB_NT_SRV_INST
		instance := spn[i+1:]
		// 4-part SPN: split off trailing /serviceName before parsing :port.
		if j := strings.Index(instance, "/"); j >= 0 {
			p.svcName = instance[j+1:]
			instance = instance[:j]
		}
		if k := strings.Index(instance, ":"); k >= 0 {
			p.port = instance[k+1:]
			instance = instance[:k]
		}
		p.host = instance
		if d := strings.Index(instance, "."); d > 0 && d < len(instance)-1 {
			p.domain = instance[d+1:]
		}
		return p
	}
	if at := strings.Index(spn, "@"); at > 0 && at < len(spn)-1 {
		p.isUPN = true
		p.upnRealm = spn[at+1:]
		return p
	}
	p.isSAM = true
	return p
}

// realmsMatch reports whether two realm strings refer to the same realm,
// tolerating NETBIOS<->DNS form mismatch (e.g. "CONTOSO" vs "CONTOSO.LOCAL").
//
// PERMISSIVE / BEST-EFFORT: this treats the first DNS label as the implicit
// NETBIOS form. This is wrong when the NETBIOS name is truncated, renamed, or
// otherwise unrelated to the DNS domain — in such environments the comparison
// can return true for two realms that are actually distinct. Users in those
// environments should pass --netbios-domain explicitly; even then the helper
// remains permissive (it's intentionally biased toward accepting tickets the
// caller probably wants to use rather than rejecting them). See README for
// caveats.
func realmsMatch(a, b string) bool {
	if a == "" || b == "" {
		return false
	}
	if strings.EqualFold(a, b) {
		return true
	}
	aFirst := strings.SplitN(a, ".", 2)[0]
	bFirst := strings.SplitN(b, ".", 2)[0]
	return strings.EqualFold(aFirst, b) || strings.EqualFold(a, bFirst)
}

func setupKRB5Client(args *userArgs) (err error) {
	// AllowDomainSuffixRealmGuess(false): kerbtool always supplies an
	// explicit dcDomain to GetServiceTicketExt, so gokrb5's suffix-strip
	// realm guess is unreachable in normal flows. Disable it explicitly so
	// the behaviour stays well-defined if a future call path leaves
	// dcDomain empty.
	settings := []func(*client.Settings){
		client.DisablePAFXFAST(true),
		client.AllowDomainSuffixRealmGuess(false),
	}
	var p uint64

	if args.username == "" {
		fmt.Println("Must specify --user when requesting a ticket!")
		myFlags.Usage()
	}
	if args.userDomain == "" {
		fmt.Println("Must provide a user domain (--domain)")
		myFlags.Usage()
	}
	// normalizeDomains must run early: userDomainUpper is consumed by the
	// NewWith* client constructors below regardless of realm resolution. The
	// user-domain fallback for dcDomain itself is deferred to the end of this
	// function so the more-specific derivations (--target-realm, --ask-referral,
	// foreign b64 TGT) get first chance to set it. See the fallback near the
	// bottom of setupKRB5Client.
	normalizeDomains(args)

	// Validate format
	if isFlagSet("dns-host") {
		parts := strings.Split(args.dnsHost, ":")
		if len(parts) < 2 {
			if args.dnsHost != "" {
				args.dnsHost += ":53"
				parts = append(parts, "53")
				log.Debugf("No port number specified for --dns-host so assuming port 53")
			} else {
				flag.Usage()
				return fmt.Errorf("Invalid --dns-host")
			}
		}
		ip := net.ParseIP(parts[0])
		if ip == nil {
			flag.Usage()
			return fmt.Errorf("Invalid --dns-host. Not a valid ip host address")
		}
		p, err = strconv.ParseUint(parts[1], 10, 32)
		if err != nil {
			return fmt.Errorf("Invalid --dns-host. Failed to parse port: %s\n", err)
		}
		if p < 1 {
			flag.Usage()
			return fmt.Errorf("Invalid --dns-host port number")
		}
	}

	if args.socksHost != "" && args.socksPort < 1 {
		flag.Usage()
		return fmt.Errorf("Invalid --socks-port")
	}

	if args.socksHost != "" {
		// Force TCP communication with KDC
		var dialSocksProxy proxy.Dialer
		args.krbConf.LibDefaults.UDPPreferenceLimit = 1
		dialSocksProxy, err = proxy.SOCKS5("tcp", fmt.Sprintf("%s:%d", args.socksHost, args.socksPort), nil, proxy.Direct)
		if err != nil {
			log.Errorln(err)
			return
		}
		if args.dnsHost != "" {
			// No dialTimout set for dns requests
			args.krbConf.SetDNSResolver(dialSocksProxy.(proxy.ContextDialer), args.dnsHost, "tcp")
		}
		settings = append(settings, client.SetProxyDialer(dialSocksProxy))
		settings = append(settings, client.SetDialTimout(args.timeout))
	} else if args.dnsHost != "" {
		protocol := "udp"
		if args.dnsTCP {
			protocol = "tcp"
		}
		args.krbConf.SetDNSResolver(&net.Dialer{Timeout: args.timeout}, args.dnsHost, protocol)
		log.Infof("Configured custom DNS resolver for Kerberos lib to be %s, protocol: %s\n", args.dnsHost, protocol)
	}

	if args.timeout < time.Second {
		err = fmt.Errorf("Valid value for the timeout is >= 1 seconds")
		return
	}

	if args.hash != nil && args.aesKey != nil {
		flag.Usage()
		return fmt.Errorf("Choose one of --hash and --aesKey for authentication")
	}
	if args.hash != nil && (len(args.hash) != 16) {
		flag.Usage()
		return fmt.Errorf("Invalid length of NT hash provided with --hash argument")
	}

	var aesKeyEType int32
	if args.aesKey != nil {
		hashLen := len(args.aesKey)
		switch hashLen {
		case 16:
			if args.sha2 {
				aesKeyEType = etypeID.AES128_CTS_HMAC_SHA256_128
			}
		case 32:
			if args.sha2 {
				aesKeyEType = etypeID.AES256_CTS_HMAC_SHA384_192
			}
		default:
			flag.Usage()
			return fmt.Errorf("Invalid length of hex for --aesKey")
		}
	}

	if args.spn == "" && (args.askST || args.kerberoast) {
		// S4U2Self+U2U doesn't need an SPN (targets the requesting user's principal)
		if !(args.askST && args.u2u && args.impersonate != "") {
			return fmt.Errorf("Must specify an SPN when requesting a service ticket or kerberoasting")
		}
	}

	// If --target-realm is explicitly set, it takes priority for dcDomain and referral target
	if args.targetRealm != "" {
		args.dcDomain = strings.ToUpper(args.targetRealm)
		args.referral = true
	}

	var target []string
	if args.spn != "" {
		if args.targetRealm != "" {
			// Explicit target realm specified — use it directly
			target = []string{"krbtgt", strings.ToUpper(args.targetRealm)}
			log.Infof("Using explicit target realm: %s\n", args.targetRealm)
		} else if args.referral {
			// Legacy --ask-referral behavior: derive realm from --dc hostname,
			// SPN's DNS suffix, or a UPN's @-suffix. NetBIOS-only SPNs and bare
			// sAMAccountNames carry no realm hint — those callers must pass
			// --target-realm explicitly (or use --dc with an FQDN).
			if args.dcHost != "" {
				parts := strings.SplitN(args.dcHost, ".", 2)
				if len(parts) > 1 && !strings.EqualFold(parts[1], args.userDomain) {
					target = []string{"krbtgt", strings.ToUpper(parts[1])}
				}
				args.dcDomain = strings.ToUpper(parts[1])
			}
			if target == nil && args.serviceDomain != "" {
				target = []string{"krbtgt", strings.ToUpper(args.serviceDomain)}
			}
			if target == nil {
				ps := parseSPN(args.spn)
				if ps.upnRealm != "" && !strings.EqualFold(ps.upnRealm, args.userDomain) {
					target = []string{"krbtgt", strings.ToUpper(ps.upnRealm)}
				}
			}
			log.Infof("referral target: %v\n", target)
		} else {
			// Non-referral: construct target for CCACHE lookup if SPN components are available
			if args.service != "" {
				if args.serviceDomain != "" {
					target = []string{args.service, args.serviceHost + "." + args.serviceDomain}
				} else if args.serviceHost != "" {
					target = []string{args.service, args.serviceHost}
				}
			}
			// If target is nil (e.g., SPN without "/"), NewFromCCache will still load TGTs
		}
	}

	/* If password is specified with --pass flag, use it to logon and then add potential ccache entries.
	If no pass is specified. Try to use potential ccache entries, otherwise fail later
	*/
	if (args.password == "") && (args.hash == nil) && (args.aesKey == nil) && (args.pfxFile == "") {
		if !args.noPass {
			var passBytes []byte
			fmt.Printf("Enter password: ")
			passBytes, err = term.ReadPassword(int(os.Stdin.Fd()))
			fmt.Println()
			if err != nil {
				log.Errorln(err)
				return
			}
			args.password = string(passBytes)
		}
	}
	if args.aesKey != nil {
		args.c, _ = client.NewWithKeyEtype(args.username, args.userDomainUpper, args.aesKey, aesKeyEType, args.krbConf, settings...)
		log.Infoln("Authenticated using aes key!")
	} else if args.hash != nil {
		args.c, _ = client.NewWithHash(args.username, args.userDomainUpper, args.hash, args.krbConf, settings...)
		log.Infoln("Authenticated using NT Hash!")
	} else if args.pfxFile != "" {
		pfxData, readErr := os.ReadFile(args.pfxFile)
		if readErr != nil {
			err = fmt.Errorf("failed to read PFX file %s: %s", args.pfxFile, readErr)
			log.Errorln(err)
			return
		}
		args.c, _ = client.NewWithPFX(args.username, args.userDomainUpper, pfxData, args.pfxPass, args.krbConf, settings...)
		log.Infoln("Authenticating using PKINIT with PFX certificate!")
	} else if args.password != "" {
		args.c, _ = client.NewWithPassword(args.username, args.userDomainUpper, args.password, args.krbConf, settings...)
		log.Infoln("Authenticated using password!")
	}
	if args.c != nil && !args.noLogin {
		err = args.c.Login()
		if err != nil {
			log.Errorf("Login failed: %s\n", err)
			return
		}
	}

	if args.c == nil && args.cache == nil {
		if args.ticketB64 != "" {
			var cred *credentials.Credential
			cred, err = b64ToCCache(args.ticketB64)
			if err != nil {
				log.Errorln(err)
				return
			}
			args.c, err = client.NewFromTicket(cred, args.krbConf, settings...)
			if err != nil {
				log.Errorf("Failed to create kerberos client from provided ticket: %s", err.Error())
			}
		}
	}

	if args.cache != nil {
		if args.c == nil {
			if args.ticketB64 != "" {
				var cred *credentials.Credential
				cred, err = b64ToCCache(args.ticketB64)
				if err != nil {
					log.Errorln(err)
					return
				}
				args.c, err = client.NewFromTicket(cred, args.krbConf, settings...)
				if err != nil {
					log.Errorf("Failed to create kerberos client from provided ticket: %s", err.Error())
				}
			} else {
				log.Debugf("Looking for ccache ticket for %v\n", target)
				// When requesting a ServiceTicket, we want to use any available TGT from the CCACHE
				args.c, err = client.NewFromCCache(args.cache, target, args.krbConf, settings...)
				if err != nil {
					log.Errorf("Tried to create kerberos client from ccache but failed with error: %s\n", err)
					err = fmt.Errorf("Found no useable credentials and no ccache entries to use")
					return
				}
			}
		} else if args.ticketB64 != "" {
			var cred *credentials.Credential
			cred, err = b64ToCCache(args.ticketB64)
			if err != nil {
				log.Errorln(err)
				return
			}
			err = args.c.AddTicketToSession(cred, "")
			if err != nil {
				log.Errorln(err)
				return
			}
		}
		// Check that principal name matches. Realm comparison is alias-aware
		// via the client's runtime alias table, which was seeded from
		// krbConf.RealmAliases at construction time and may be extended by
		// NewFromCCacheWithFallbacks when a krbtgt entry differs in form.
		if args.cache.DefaultPrincipal.PrincipalName.Equal(args.c.Credentials.CName()) && args.c.IsSameRealm(args.cache.DefaultPrincipal.Realm, args.c.Credentials.Realm()) {
			log.Infoln("Adding ccache entries to client")
			// Only need to add old ccache entries if we could not create a client from the old ccache
			args.c.AddCacheEntries(args.cache)
		} else {
			log.Infoln("Tickets in CCACHE are for another principal so will not be used")
			args.cache = nil
		}

		if args.askST && args.ticketB64 == "" {
			/*
				When requesting a service ticket, we could either use a cached TGT, a referral ticket for the appropriate domain or provided credentials
			*/
			if args.referral {
				// Check if we have a referral ticket for the target domain
				_, _, err = args.c.GetTGT(target[1])
			} else {
				// Use whatever realm form the client/ccache was actually loaded
				// with (DNS or NETBIOS). gokrb5's session map is keyed on the
				// literal realm string of the stored TGT, so asking for a
				// different form here would miss the session.
				_, _, err = args.c.GetTGT(args.c.Credentials.Realm())
			}
			if err != nil {
				// Found no usable TGT
				args.c = nil
			}
		}
	}
	if args.c == nil {
		err = fmt.Errorf("Found no useable credentials and no ccache entries to use")
		return
	}

	// Resolve the default target realm now that --target-realm / --ask-referral
	// and any supplied b64 TGT have had their chance to set dcDomain. Order
	// matters: a foreign b64 ticket's own realm takes precedence over the
	// user-domain fallback (edge case: requesting a ticket for a foreign domain
	// from an on-prem DC).
	if args.dcDomain == "" && args.ticketB64 != "" {
		args.dcDomain = args.c.Credentials.Realm()
	}
	if args.dcDomain == "" {
		// In the common single-domain case, request the ticket in the user's
		// own realm. AD realms are uppercase and case-sensitive on the wire;
		// session-cache lookups are case-insensitive via CanonicalRealm.
		args.dcDomain = args.userDomainUpper
	}

	return
}

func saveToCCACHE(args *userArgs, ticket *messages.Ticket, decryptedEncPart *messages.EncTicketPart, spn string, includeAllTickets bool) (err error) {
	w := bytes.NewBuffer([]byte{})
	cache := credentials.NewV4CCache()
	clientPrincipal := types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, args.username)
	principal := credentials.NewPrincipal(clientPrincipal, args.userDomainUpper)
	cache.SetDefaultPrincipal(principal)
	if includeAllTickets {
		if args.altService != "" {
			// First save ticket with replaced sname
			err = args.c.SaveSPNToCCache(cache, clientPrincipal, args.userDomainUpper, spn, args.altService)
			if err != nil {
				log.Errorln(err)
				return
			}
		}
		// Then save any additional tickets from the cache
		err = args.c.SaveAllTicketsToCCache(cache, clientPrincipal, args.userDomainUpper)
		if err != nil {
			log.Errorln(err)
			return
		}
	} else if spn != "" {
		cache.SetKDCTimeOffset(0xFFFFFFFF, 0) // Any better value here?
		if args.impersonate != "" {
			clientPrincipal = types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, args.impersonate)
			principal := credentials.NewPrincipal(clientPrincipal, args.userDomainUpper)
			cache.SetDefaultPrincipal(principal)
		}
		err = args.c.SaveSPNToCCache(cache, clientPrincipal, args.userDomainUpper, spn, args.altService)
		if err != nil {
			log.Errorln(err)
			return
		}
	} else {
		var ticketBytes []byte
		ticketBytes, err = ticket.Marshal()
		if err != nil {
			log.Errorln(err)
			return
		}
		clientPrincipal := decryptedEncPart.CName
		if args.impersonate != "" {
			clientPrincipal = types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, args.impersonate)
		}

		principal := credentials.NewPrincipal(clientPrincipal, decryptedEncPart.CRealm)
		kdcPrincipal := credentials.NewPrincipal(ticket.SName, ticket.Realm)
		cred := &credentials.Credential{
			Client:      principal,
			Server:      kdcPrincipal,
			Key:         decryptedEncPart.Key,
			AuthTime:    decryptedEncPart.AuthTime,
			StartTime:   decryptedEncPart.StartTime,
			EndTime:     decryptedEncPart.EndTime,
			RenewTill:   decryptedEncPart.RenewTill,
			TicketFlags: decryptedEncPart.Flags,
			Ticket:      ticketBytes,
		}

		cache = credentials.NewV4CCache()
		cache.SetKDCTimeOffset(0xFFFFFFFF, 0) // Any better value here?
		cache.SetDefaultPrincipal(principal)

		// Add forged tickets to existing or new ccache
		cache.AddCredential(cred)
	}

	var b []byte
	b, err = cache.Marshal()
	if err != nil {
		log.Errorln(err)
		return
	}
	_, err = w.Write(b)
	if err != nil {
		log.Errorln(err)
		return
	}

	f, err := os.OpenFile(args.targetFile, os.O_CREATE|os.O_TRUNC|os.O_RDWR, 0600)
	if err != nil {
		log.Errorf("Failed to open file for writing: %s\n", err)
		return
	}
	defer f.Close()
	_, err = f.Write(w.Bytes())
	if err != nil {
		log.Errorln(err)
		return
	}
	fmt.Printf("Wrote Ticket(s) to file %s\n", args.targetFile)
	return
}

func main() {
	var err error

	action, args, _ := handleArgs()

	if args.debug {
		golog.Set("github.com/jfjallid/go-smb/msdtyp", "msdtyp", golog.LevelDebug, golog.LstdFlags|golog.Lshortfile, golog.DefaultOutput, golog.DefaultErrOutput)
		log.SetFlags(golog.LstdFlags | golog.Lshortfile)
		log.SetLogLevel(golog.LevelDebug)
	} else if args.verbose {
		golog.Set("github.com/jfjallid/go-smb/msdtyp", "msdtyp", golog.LevelInfo, golog.LstdFlags|golog.Lshortfile, golog.DefaultOutput, golog.DefaultErrOutput)
		log.SetFlags(golog.LstdFlags | golog.Lshortfile)
		log.SetLogLevel(golog.LevelInfo)
	} else {
		golog.Set("github.com/jfjallid/go-smb/msdtyp", "msdtyp", golog.LevelNotice, golog.LstdFlags|golog.Lshortfile, golog.DefaultOutput, golog.DefaultErrOutput)
	}

	if args.version {
		printVersion()
		return
	}

	// Compute userDomainUpper + netbiosDomain(Upper) up front so the ccache
	// acceptance check below and the krbConf builder further down can both rely
	// on them. setupKRB5Client also calls this (idempotent) for the paths that
	// reach it without going through main().
	normalizeDomains(args)

	args.ccacheFile = os.Getenv("KRB5CCNAME")

	if args.ccacheFile != "" {
		log.Infof("Trying to load Kerberos tickets from CCACHE file at %s\n", args.ccacheFile)
		args.cache, err = credentials.LoadCCache(args.ccacheFile)
		if err != nil {
			if os.IsNotExist(err) {
				log.Infoln("CCACHE file was empty")
			} else {
				log.Infof("Failed to parse CCACHE file referenced by KRB5CCNAME and got error: %s\n", err)
			}
			args.cache = nil
			err = nil
		}
		if isFlagSet("user") && args.cache != nil {
			if !strings.EqualFold(args.username, args.cache.GetClientPrincipalName().PrincipalNameString()) {
				log.Infoln("Tickets in CCACHE are for another principal so will not be used")
				args.cache = nil
			}
		}
		if isFlagSet("domain") && args.cache != nil {
			// Pre-client check: krbConf and the gokrb5 alias table don't exist
			// yet at this point, so use the local realmsMatch heuristic. It is
			// strictly more permissive than the alias-aware comparison the
			// rest of the codebase uses post-construction, which is the right
			// bias for ccache acceptance — anything the alias table would
			// accept later, realmsMatch also accepts.
			cacheRealm := args.cache.GetClientRealm()
			if !realmsMatch(args.userDomain, cacheRealm) && !realmsMatch(args.netbiosDomain, cacheRealm) {
				log.Infoln("Tickets in CCACHE are for another domain so will not be used")
				args.cache = nil
			}
		}
	}
	if args.cache == nil {
		args.ccacheFile = ""
	}

	var dcTarget string
	if args.dc != "" {
		// Determine if hostname or ip
		result := net.ParseIP(args.dc)
		if result != nil {
			args.dcIP = args.dc
		} else {
			args.dcHost = args.dc
		}
		dcTarget = fmt.Sprintf("%s:%d", args.dc, args.port)

	} else {
		dcTarget = fmt.Sprintf("%s:%d", args.userDomain, args.port)
	}
	if args.krb5ConfFile != "" {
		f, err := os.Open(args.krb5ConfFile)
		if err != nil {
			log.Errorln(err)
			return
		}
		defer f.Close()
		args.krbConf, err = config.NewFromReader(f)
		if err != nil {
			log.Errorf("error parsing krb5 conf: %s\n", err)
			return
		}
	} else {
		args.krbConf = config.New()
		args.krbConf.LibDefaults.DNSLookupKDC = true
		args.krbConf.LibDefaults.DefaultRealm = strings.ToUpper(args.userDomain)
		// When --dc is specified but --target-realm points to a different realm,
		// the explicit --dc is for the target realm, not the user's home realm.
		// Use the user domain for DNS-based KDC lookup instead.
		userRealmKDC := dcTarget
		if args.targetRealm != "" && args.dc != "" && !strings.EqualFold(args.targetRealm, args.userDomain) {
			userRealmKDC = fmt.Sprintf("%s:%d", args.userDomain, args.port)
		}
		args.krbConf.Realms = append(args.krbConf.Realms, config.Realm{Realm: strings.ToUpper(args.userDomain), KDC: []string{userRealmKDC}})
		// Register a NETBIOS realm alias pointing to the same KDC, so tickets
		// whose realm is the NETBIOS form (e.g. "CONTOSO" instead of
		// "CONTOSO.LOCAL") can still be resolved/used. The default NETBIOS form
		// is derived from the first DNS label and may be wrong in environments
		// where the NETBIOS name was truncated or renamed — use
		// --netbios-domain to override. Only applied when we built krbConf
		// ourselves; a user-supplied --krb5-conf is left untouched.
		if args.netbiosDomainUpper != "" && !strings.EqualFold(args.netbiosDomainUpper, args.userDomainUpper) {
			log.Infof("Registering NETBIOS realm alias %s -> KDC %s\n", args.netbiosDomainUpper, userRealmKDC)
			args.krbConf.Realms = append(args.krbConf.Realms, config.Realm{Realm: args.netbiosDomainUpper, KDC: []string{userRealmKDC}})
			if args.krbConf.DomainRealm == nil {
				args.krbConf.DomainRealm = config.DomainRealm{}
			}
			// Seed [domain_realm] so ResolveRealm() maps the DNS domain to its
			// canonical (DNS) realm form, keeping NETBIOS strictly as an alias.
			args.krbConf.DomainRealm["."+strings.ToLower(args.userDomain)] = args.userDomainUpper
			args.krbConf.DomainRealm[strings.ToLower(args.userDomain)] = args.userDomainUpper
			// Register the pair in gokrb5's alias table so its alias-aware
			// session map treats the two forms as one realm. The Client
			// constructor copies a snapshot of RealmAliases into its own
			// per-client table, so this must run before setupKRB5Client.
			if args.krbConf.RealmAliases != nil {
				args.krbConf.RealmAliases.Add(args.netbiosDomainUpper, args.userDomainUpper)
			}
		}
		args.krbConf.LibDefaults.Forwardable = true
		if !isFlagSet("duration") {
			args.ticketDuration = time.Hour * 10
		}
		args.krbConf.LibDefaults.RenewLifetime = args.ticketDuration
		args.krbConf.LibDefaults.TicketLifetime = args.ticketDuration
		args.krbConf.LibDefaults.DefaultTGSEnctypeIDs = []int32{etypeID.AES256_CTS_HMAC_SHA384_192, etypeID.AES128_CTS_HMAC_SHA256_128, etypeID.AES256_CTS_HMAC_SHA1_96, etypeID.AES128_CTS_HMAC_SHA1_96, etypeID.RC4_HMAC}
		args.krbConf.LibDefaults.DefaultTktEnctypeIDs = []int32{etypeID.AES256_CTS_HMAC_SHA384_192, etypeID.AES128_CTS_HMAC_SHA256_128, etypeID.AES256_CTS_HMAC_SHA1_96, etypeID.AES128_CTS_HMAC_SHA1_96, etypeID.RC4_HMAC}
		types.UnsetFlag(&args.krbConf.LibDefaults.KDCDefaultOptions, flags.RenewableOK) //TODO Remove?
		// Determine if DC and userdomain are same realm
		if args.dcHost != "" {
			parts := strings.Split(args.dcHost, ".")
			if len(parts) < 3 {
				// Not a hostname
				log.Errorf("Invalid --dc argument. Expected <host>.<domain>.<tld>, not: %s\n", args.dcHost)
				return
			}
			dcDomain := strings.Join(parts[1:], ".")
			if !strings.EqualFold(dcDomain, args.userDomain) {
				log.Infof("Adding extra kerberos realm to config for realm: %s and KDC: %s\n", dcDomain, args.dcHost)
				args.krbConf.Realms = append(args.krbConf.Realms, config.Realm{Realm: strings.ToUpper(dcDomain), KDC: []string{args.dcHost + ":88"}})
			}
		}
	}
	if args.requestRC4 {
		args.krbConf.LibDefaults.DefaultTGSEnctypeIDs = []int32{etypeID.RC4_HMAC}
		args.krbConf.LibDefaults.DefaultTktEnctypeIDs = []int32{etypeID.RC4_HMAC}
	} else if args.hash != nil {
		// NT hash can only derive RC4 keys. If the AS-REQ advertises AES256,
		// a KDC may encrypt the AS-REP with AES256 (especially for accounts
		// with DoesNotRequirePreAuth where no pre-auth hints the etype).
		// Restrict both ticket and TGS etypes to RC4 so the response is
		// decryptable on every leg of the handshake; the SHA-2 entries now
		// in the default TGS list would otherwise leave room for the KDC to
		// pick an enctype we cannot key.
		args.krbConf.LibDefaults.DefaultTktEnctypeIDs = []int32{etypeID.RC4_HMAC}
		args.krbConf.LibDefaults.DefaultTGSEnctypeIDs = []int32{etypeID.RC4_HMAC}
	}

	if args.spn != "" {
		ps := parseSPN(args.spn)
		args.service = ps.service
		args.serviceFQDN = ps.fqdnLike()
		args.serviceDomain = ps.domain
		// Legacy semantic: args.serviceHost is the first DNS label only,
		// used together with args.serviceDomain to reconstruct an FQDN for
		// CCache target lookups (see target derivation in setupKRB5Client).
		if i := strings.Index(ps.host, "."); i > 0 {
			args.serviceHost = ps.host[:i]
		} else {
			args.serviceHost = ps.host
		}
		args.serviceNameType = ps.nameType
	} else {
		args.serviceNameType = nametype.KRB_NT_ENTERPRISE
	}

	// When --target-realm is set with a --dc, add the realm to the kerberos config
	if args.targetRealm != "" && args.dcHost != "" {
		targetRealmUpper := strings.ToUpper(args.targetRealm)
		if !strings.EqualFold(targetRealmUpper, args.userDomainUpper) {
			log.Infof("Adding kerberos realm to config for target realm: %s and KDC: %s\n", targetRealmUpper, args.dcHost)
			args.krbConf.Realms = append(args.krbConf.Realms, config.Realm{Realm: targetRealmUpper, KDC: []string{args.dcHost + ":88"}})
			// Also register a NETBIOS alias for the target realm pointing at
			// the same KDC, using the first-DNS-label heuristic (see
			// realmsMatch() caveats). There is no per-target-realm override
			// flag; users who hit a mismatch here can supply a full
			// --krb5-conf instead.
			if strings.Contains(targetRealmUpper, ".") {
				targetNB := strings.SplitN(targetRealmUpper, ".", 2)[0]
				if !strings.EqualFold(targetNB, targetRealmUpper) {
					log.Infof("Registering NETBIOS realm alias %s -> KDC %s for target realm\n", targetNB, args.dcHost)
					args.krbConf.Realms = append(args.krbConf.Realms, config.Realm{Realm: targetNB, KDC: []string{args.dcHost + ":88"}})
					if args.krbConf.RealmAliases != nil {
						args.krbConf.RealmAliases.Add(targetNB, targetRealmUpper)
					}
				}
			}
		}
	}
	if args.asRepRoast {
		args.noLogin = true
		if args.password == "" {
			args.password = "Fake Password" // Hack to allow client to initialize
		}
	}

	if args.askTGT || args.askST || args.request || args.kerberoast || args.asRepRoast {
		err = setupKRB5Client(args)
		if err != nil {
			log.Errorln(err)
			return
		}
	}

	switch action {
	case 1:
		err = handleAskTGT(args)
		if err != nil {
			log.Errorln(err)
			return
		}
		return
	case 2:
		err = handleAskST(args)
		if err != nil {
			log.Errorln(err)
			return
		}
	case 3:
		err = handleForge(args)
		if err != nil {
			log.Errorln(err)
			return
		}
	case 4:
		err = handleParseTicket(args)
		if err != nil {
			log.Errorln(err)
			return
		}
	case 5:
		err = handleConvertTicket(args)
		if err != nil {
			log.Errorln(err)
			return
		}
	case 6:
		err = handleKerberoast(args)
		if err != nil {
			log.Errorln(err)
			return
		}
	case 7:
		err = handleASReperoast(args)
		if err != nil {
			log.Errorln(err)
			return
		}
	}
	if args.c != nil {
		defer args.c.Destroy()
	}

	return
}
