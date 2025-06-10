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

	"github.com/jfjallid/gokrb5/v8/client"
	"github.com/jfjallid/gokrb5/v8/config"
	"github.com/jfjallid/gokrb5/v8/credentials"
	"github.com/jfjallid/gokrb5/v8/types"

	"github.com/jfjallid/gokrb5/v8/iana/etypeID"
	"github.com/jfjallid/gokrb5/v8/iana/flags"
	"github.com/jfjallid/gokrb5/v8/iana/nametype"

	"github.com/jfjallid/gokrb5/v8/messages"
	"github.com/jfjallid/mstypes"
)

var log = golog.Get("")
var release string = "0.1.1"
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
      ` + helpConnectionOptions + `
`
var helpGeneralOptions = `
          --debug                 Enable debug logging
          --verbose               Enable verbose logging
      -v, --version               Show version
`
var helpConnectionOptions = `
    General options:
      -P, --port <port>           Kerberos Port (default 88)
      -d, --domain <domain>       Domain name to use for login
      -u, --user <username>       Username
      -p, --pass <pass>           Password
          --hash <NT Hash>        Hex encoded NT Hash for user password
      -n, --no-pass               Do not prompt for password
          --dc <fqdn/ip>          Optionally specify fqdn or ip of KDC when requesting tickets
          --aes-key <AES key>     Use a hex encoded AES128/256 key for Kerberos authentication
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
	for i, _ := range parts {
		str := strings.TrimSpace(parts[i])
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
	for i, _ := range parts {
		str := strings.TrimSpace(parts[i])
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
	socksHost  string
	dcIP       string
	dc         string // Hostname or ip
	dcHost     string
	dcDomain   string
	aesKey     binaryArg
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
	askTGT     bool
	askST      bool
	forge      bool
	parse      bool
	convert    bool
	kerberoast bool
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
	dumpAllTickets bool
	// Non-user arguments
	serviceDomain   string
	templateTicket  messages.Ticket
	referral        bool
	serviceFQDN     string
	service         string
	serviceHost     string
	signingKey      []byte
	signAes128Key   bool
	signAes256Key   bool
	signAes         bool
	userDomainUpper string
	ccacheFile      string // KRB5CCACHE filename
}

func addConnectionArgs(flagSet *flag.FlagSet, argv *userArgs) {
	flagSet.StringVar(&argv.username, "u", "", "")
	flagSet.StringVar(&argv.username, "user", "", "")
	flagSet.StringVar(&argv.password, "p", "", "")
	flagSet.StringVar(&argv.password, "pass", "", "")
	flagSet.Var(&argv.hash, "hash", "")
	flagSet.StringVar(&argv.userDomain, "d", "", "")
	flagSet.StringVar(&argv.userDomain, "domain", "", "")
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
	flagSet.StringVar(&argv.dnsHost, "dns-host", "", "")
	flagSet.BoolVar(&argv.dnsTCP, "dns-tcp", false, "")
	flagSet.BoolVar(&argv.noPass, "n", false, "")
	flagSet.BoolVar(&argv.noPass, "no-pass", false, "")
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
	flagSet.StringVar(&argv.spn, "spn", "", "")
	flagSet.StringVar(&argv.krb5ConfFile, "krb5-conf", "", "")
	flagSet.StringVar(&argv.targetUsername, "target", "", "")
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

func setupKRB5Client(args *userArgs) (err error) {
	settings := []func(*client.Settings){client.DisablePAFXFAST(true)}
	var p uint64

	if args.username == "" {
		fmt.Println("Must specify --user when requesting a ticket!")
		myFlags.Usage()
	}
	if args.userDomain == "" {
		fmt.Println("Must provid a user domain (--domain)")
		myFlags.Usage()
	}
	args.userDomainUpper = strings.ToUpper(args.userDomain)

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

	if args.aesKey != nil {
		hashLen := len(args.aesKey)
		switch hashLen {
		case 16, 32:
		default:
			flag.Usage()
			return fmt.Errorf("Invalid length of hex for --aesKey")
		}
	}

	if args.spn == "" && (args.askST || args.kerberoast) {
		return fmt.Errorf("Must specify an SPN when requesting a service ticket or kerberoasting")
	}

	var target []string
	if args.spn != "" {
		if args.referral {
			// Is this always krbtgt?
			if args.dcHost != "" {
				parts := strings.SplitN(args.dcHost, ".", 2)
				if len(parts) > 1 && !strings.EqualFold(parts[1], args.userDomain) {
					// Look for a referral ticket for the Domain controller's domain
					target = []string{"krbtgt", strings.ToUpper(parts[1])}
				}
				args.dcDomain = strings.ToUpper(parts[1]) // is this correct?
			}
			if target == nil {
				target = []string{"krbtgt", strings.ToUpper(args.serviceDomain)}
			}
			log.Infof("referral target: %v\n", target)
		} else {
			target = []string{args.service, args.serviceHost + "." + args.serviceDomain}
		}
	}

	/* If password is specified with --pass flag, use it to logon and then add potential ccache entries.
	If no pass is specified. Try to use potential ccache entries, otherwise fail later
	*/
	if (args.password == "") && (args.hash == nil) && (args.aesKey == nil) {
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
		args.c = client.NewWithKey(args.username, strings.ToUpper(args.userDomain), args.aesKey, args.krbConf, settings...)
		log.Infoln("Authenticated using aes key!")
	} else if args.hash != nil {
		args.c = client.NewWithHash(args.username, strings.ToUpper(args.userDomain), args.hash, args.krbConf, settings...)
		log.Infoln("Authenticated using NT Hash!")
	} else if args.password != "" {
		args.c = client.NewWithPassword(args.username, strings.ToUpper(args.userDomain), args.password, args.krbConf, settings...)
		log.Infoln("Authenticated using password!")
	}
	if args.c != nil {
		err = args.c.Login()
		if err != nil {
			log.Errorf("Login failed: %s\n", err)
			return
		}
	}

	if args.cache != nil {
		if args.c == nil {
			log.Debugf("Looking for ccache ticket for %v\n", target)
			// When requesting a ServiceTicket, we want to use any available TGT from the CCACHE
			args.c, err = client.NewFromCCache(args.cache, target, args.krbConf, settings...)
			if err != nil {
				log.Errorf("Tried to create kerberos client from ccache but failed with error: %s\n", err)
				err = fmt.Errorf("Found no useable credentials and no ccache entries to use")
				return
			}
		}
		// Check that principal name matches
		if args.cache.DefaultPrincipal.PrincipalName.Equal(args.c.Credentials.CName()) && args.cache.DefaultPrincipal.Realm == args.c.Credentials.Realm() {
			log.Infoln("Adding ccache entries to client")
			// Only need to add old ccache entries if we could not create a client from the old ccache
			args.c.AddCacheEntries(args.cache)
		} else {
			log.Infoln("Tickets in CCACHE are for another principal so will not be used")
			args.cache = nil
		}

		if args.askST {
			/*
				When requesting a service ticket, we could either use a cached TGT, a referral ticket for the appropriate domain or provided credentials
			*/
			if args.referral {
				// Check if we have a referral ticket for the target domain
				_, _, err = args.c.GetTGT(target[1])
			} else {
				_, _, err = args.c.GetTGT(strings.ToUpper(args.userDomain))
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
			if !strings.EqualFold(args.userDomain, args.cache.GetClientRealm()) {
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
			log.Errorf("error paring krb5 conf: %s\n", err)
			return
		}
	} else {
		args.krbConf = config.New()
		args.krbConf.LibDefaults.DNSLookupKDC = true
		args.krbConf.LibDefaults.DefaultRealm = strings.ToUpper(args.userDomain)
		args.krbConf.Realms = append(args.krbConf.Realms, config.Realm{Realm: strings.ToUpper(args.userDomain), KDC: []string{dcTarget}}) // or should KDC be empty to trigger lookup?
		args.krbConf.LibDefaults.Forwardable = true
		if !isFlagSet("duration") {
			args.ticketDuration = time.Hour * 10
		}
		args.krbConf.LibDefaults.RenewLifetime = args.ticketDuration
		args.krbConf.LibDefaults.TicketLifetime = args.ticketDuration
		args.krbConf.LibDefaults.DefaultTGSEnctypeIDs = []int32{etypeID.AES256_CTS_HMAC_SHA1_96, etypeID.AES128_CTS_HMAC_SHA1_96, etypeID.RC4_HMAC}
		args.krbConf.LibDefaults.DefaultTktEnctypeIDs = []int32{etypeID.AES256_CTS_HMAC_SHA1_96, etypeID.AES128_CTS_HMAC_SHA1_96, etypeID.RC4_HMAC}
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
	}

	if args.spn != "" {
		//TODO Support other format of SPN with backslash?
		parts := strings.Split(args.spn, "/")
		if len(parts) != 2 {
			log.Errorln("Invalid SPN!")
			return
		}
		//TODO Maybe this shouldn't be enforced as a valid SPN might be non-fqdn?
		if !strings.Contains(parts[1], ".") {
			log.Noticeln("Using SPN with netbios name and not FQDN")
		}
		args.service = parts[0]
		args.serviceFQDN = parts[1]
		if strings.EqualFold(args.service, "krbtgt") {
			upperFQDN := strings.ToUpper(args.serviceFQDN)
			if !strings.EqualFold(args.userDomain, args.serviceFQDN) {
				// Cross realm ticket
				args.referral = true
			}
			args.serviceDomain = upperFQDN
			args.spn = "krbtgt/" + upperFQDN
		} else {
			parts = strings.SplitN(args.serviceFQDN, ".", 2)
			if len(parts) > 1 {
				args.serviceDomain = parts[1]
			}
			args.serviceHost = parts[0]
			if !strings.EqualFold(args.serviceDomain, args.userDomain) {
				args.referral = true
			}
		}
	}

	if args.askTGT || args.askST || args.request || args.kerberoast {
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
	}
	if args.c != nil {
		defer args.c.Destroy()
	}

	return
}
