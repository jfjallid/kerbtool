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
	"encoding/binary"
	"fmt"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/jfjallid/gofork/encoding/asn1"
	"github.com/jfjallid/gokrb5/v8/client"
	"github.com/jfjallid/gokrb5/v8/config"
	"github.com/jfjallid/gokrb5/v8/credentials"
	"github.com/jfjallid/gokrb5/v8/crypto"
	"github.com/jfjallid/gokrb5/v8/iana/chksumtype"
	"github.com/jfjallid/gokrb5/v8/iana/etypeID"
	"github.com/jfjallid/gokrb5/v8/iana/flags"
	"github.com/jfjallid/gokrb5/v8/iana/keyusage"
	"github.com/jfjallid/gokrb5/v8/iana/nametype"
	"github.com/jfjallid/gokrb5/v8/iana/patype"
	"github.com/jfjallid/gokrb5/v8/messages"
	"github.com/jfjallid/gokrb5/v8/types"
)

var helpAskSTOptions = `
    Usage: ` + os.Args[0] + ` --ask-st [options]
    ` + helpConnectionOptions + `
    options:
          --spn	<SPN>             SPN to request a service ticket for. Supports service/FQDN, service/host, UPN, sAMAccountName
          --target-realm <realm>  Explicitly set target Kerberos realm for the SPN (useful for cross-domain or Entra SSO)
          --ask-referral          Force referral ticket handling (legacy, prefer --target-realm). Does not work for external trust
          --sign-nt <NT Hash>     Hex encoded NT Hash of key to sign or decrypt ticket with
          --sign-aes <AES key>    Hex encoded AES128/256 key to sign or decrypt ticket with
          --impersonate <user>    Impersonate target username through S4U. Requires delegation to be setup
          --dump-all              Write all tickets to the CCache file
          --out-file <path>       Filename to write requested ticket to (default creds.ccache unless KRB5CCNAME is set)
          --inspect               Inspect content of requested, forged or parsed ticket. Requires --sign-nt or --sign-aes
          --request-rc4           Ask for RC4 encrypted encPart of KDC REP, not the actual ticket (default false)
          --alt-service <SPN>     Override sname/SPN in ticket. Works if both services share account password.
          --u2u                   Request User-to-User ticket (enc-tkt-in-skey)
          --additional-ticket <file> Path to file (ccache/kirbi) containing the target user's TGT for plain U2U
          --krb5-conf <file>      Read krb5.conf file and use as config
          --duration <duration>   Ticket validity duration for crafted tickets. Format 8h, 30m. (default 10h)
          --ticket <b64>          Base64 string of TGT to use for authentication (CCACHE an KIRBI supported).
`

func handleAskST(args *userArgs) (err error) {
	if args.signKeyNT != nil && args.signKeyAES != nil && args.inspect {
		return fmt.Errorf("choose ONE of --sign-nt and --sign-aes when inspecting tickets")
	}
	if args.signKeyNT == nil && args.signKeyAES == nil && args.inspect {
		return fmt.Errorf("must provide a decryption key with either --sign-nt or --sign-aes when inspecting a ticket")
	}
	if args.signKeyNT != nil && (len(args.signKeyNT) != 16) {
		return fmt.Errorf("invalid length of NT hash provided with --sign-nt argument")
	}
	if args.signKeyAES != nil {
		hashLen := len(args.signKeyAES)
		switch hashLen {
		case 16:
			args.signAes128Key = true
		case 32:
			args.signAes256Key = true
		default:
			return fmt.Errorf("invalid length of hex for --sign-aes: %d", hashLen)
		}
	}
	if args.inspect {
		if args.signAes128Key || args.signAes256Key {
			args.signingKey = args.signKeyAES
			args.signAes = true
		} else {
			args.signingKey = args.signKeyNT
		}
	}

	// U2U validation
	if args.u2u && args.impersonate == "" && args.additionalTicketFile == "" {
		return fmt.Errorf("--u2u without --impersonate requires --additional-ticket with the target user's TGT")
	}
	if args.u2u && args.impersonate == "" && args.spn == "" {
		return fmt.Errorf("--u2u without --impersonate requires --spn with the target user's principal")
	}
	if args.additionalTicketFile != "" && !args.u2u {
		return fmt.Errorf("--additional-ticket requires --u2u")
	}
	if args.u2u && args.impersonate != "" && args.spn != "" {
		log.Warningln("--spn is ignored when using --u2u with --impersonate (S4U2Self+U2U)")
	}

	if !isFlagSet("out-file") {
		if args.u2u && args.impersonate != "" {
			// S4U2Self+U2U: ticket sname is the requesting user
			args.targetFile = fmt.Sprintf("%s@%s@%s.ccache", args.impersonate, args.username, args.userDomainUpper)
		} else if args.ccacheFile != "" && args.impersonate == "" {
			fmt.Println("Going to write ticket to existing ccache file")
			args.targetFile = args.ccacheFile
			args.dumpAllTickets = true
		} else if args.impersonate != "" {
			args.targetFile = fmt.Sprintf("%s@%s_%s@%s.ccache", args.impersonate, args.service, args.serviceFQDN, args.userDomainUpper)
		} else if args.altService != "" {
			parts := strings.Split(args.altService, "/")
			if len(parts) > 1 {
				args.targetFile = fmt.Sprintf("%s@%s_%s@%s.ccache", args.username, parts[0], parts[1], args.userDomainUpper)
			} else {
				args.targetFile = fmt.Sprintf("%s@%s_%s@%s.ccache", args.username, parts[0], args.serviceFQDN, args.userDomainUpper)
			}
		} else {
			args.targetFile = fmt.Sprintf("%s@%s_%s@%s.ccache", args.username, args.service, args.serviceFQDN, args.userDomainUpper)
		}
	}

	targetSPN, err := getServiceTicket(args)
	if err != nil {
		log.Errorln(err)
		return
	}
	err = saveToCCACHE(args, nil, nil, targetSPN, args.dumpAllTickets)
	if err != nil {
		log.Errorln(err)
		return
	}
	return
}

func doS4U2Proxy(c *client.Client, conf *config.Config, username, userDomain string, impersonate string, tgt messages.Ticket, st messages.Ticket, sessionKey types.EncryptionKey, spn string) (err error) {
	auth, err := types.NewAuthenticator(strings.ToUpper(userDomain), types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, username))
	if err != nil {
		log.Errorln(err)
		return
	}
	apReq, err := messages.NewAPReq(tgt, sessionKey, auth)
	if err != nil {
		log.Errorln(err)
		return
	}
	apReqBytes, err := apReq.Marshal()
	if err != nil {
		log.Errorln(err)
		return
	}

	tgsReq, err := messages.NewS4UTGSReq(types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, impersonate), types.NewPrincipalName(nametype.KRB_NT_SRV_INST, spn), tgt.Realm, conf)
	if err != nil {
		log.Errorln(err)
		return
	}
	tgsReq.PAData = types.PADataSequence{
		types.PAData{
			PADataType:  patype.PA_TGS_REQ,
			PADataValue: apReqBytes,
		},
	}

	// Set PaDATA Pacoptions
	paPacOptBytes, err := types.GetPAPacOptionsAsnMarshalled([]int{3}) // resource-based-contrained-delegation
	if err != nil {
		log.Errorln(err)
		return
	}
	pa := types.PAData{
		PADataType:  patype.PA_PAC_OPTIONS,
		PADataValue: paPacOptBytes,
	}
	tgsReq.PAData = append(tgsReq.PAData, pa)

	// Set additional ticket to ST
	tgsReq.ReqBody.AdditionalTickets = append(tgsReq.ReqBody.AdditionalTickets, st)
	opts := types.NewKrbFlags()
	types.SetFlags(&opts, []int{flags.Canonicalize, flags.Forwardable, flags.Renewable, flags.CnameInAddlTkt})
	tgsReq.KDCReqFields.ReqBody.KDCOptions = opts

	_, _, err = c.TGSExchange(tgsReq, tgt.Realm, tgt, sessionKey, 0)
	if err != nil {
		log.Errorln(err)
		return
	}

	return
}

// paForUserChksumType returns the PA-FOR-USER checksum type that matches the
// TGT session key's enctype family. Post CVE-2025-60704 (I think) KDCs verify the
// checksum using an algorithm derived from the session key, ignoring the
// declared cksumtype, so the two must agree or the KDC returns
// KRB_AP_ERR_MODIFIED.
func paForUserChksumType(k types.EncryptionKey) (int32, error) {
	switch k.KeyType {
	case etypeID.AES256_CTS_HMAC_SHA1_96:
		return chksumtype.HMAC_SHA1_96_AES256, nil
	case etypeID.AES128_CTS_HMAC_SHA1_96:
		return chksumtype.HMAC_SHA1_96_AES128, nil
	case etypeID.AES256_CTS_HMAC_SHA384_192:
		return chksumtype.HMAC_SHA384_192_AES256, nil
	case etypeID.AES128_CTS_HMAC_SHA256_128:
		return chksumtype.HMAC_SHA256_128_AES128, nil
	case etypeID.RC4_HMAC:
		return chksumtype.KERB_CHECKSUM_HMAC_MD5, nil
	default:
		return 0, fmt.Errorf("unsupported session key enctype %d for PA-FOR-USER checksum", k.KeyType)
	}
}

func doS4U2Self(c *client.Client, conf *config.Config, username, userDomain string, impersonate string, tgt messages.Ticket, sessionKey types.EncryptionKey) (st messages.Ticket, err error) {
	auth, err := types.NewAuthenticator(strings.ToUpper(userDomain), types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, username))
	if err != nil {
		log.Errorln(err)
		return
	}

	apReq, err := messages.NewAPReq(tgt, sessionKey, auth)
	if err != nil {
		log.Errorln(err)
		return
	}
	apReqBytes, err := apReq.Marshal()
	if err != nil {
		log.Errorln(err)
		return
	}

	tgsReq, err := messages.NewS4UTGSReq(types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, impersonate), types.NewPrincipalName(nametype.KRB_NT_UNKNOWN, username), tgt.Realm, conf)
	if err != nil {
		log.Errorln(err)
		return
	}
	tgsReq.PAData = types.PADataSequence{
		types.PAData{
			PADataType:  patype.PA_TGS_REQ,
			PADataValue: apReqBytes,
		},
	}

	s4uByteArray := bytes.NewBuffer([]byte{})
	binary.Write(s4uByteArray, binary.LittleEndian, nametype.KRB_NT_PRINCIPAL)
	binary.Write(s4uByteArray, binary.LittleEndian, []byte(impersonate+userDomain+"Kerberos"))

	cksumID, err := paForUserChksumType(sessionKey)
	if err != nil {
		log.Errorln(err)
		return
	}
	checksumEtype, err := crypto.GetChksumEtype(cksumID)
	if err != nil {
		log.Errorln(err)
		return
	}
	cksumHash, err := checksumEtype.GetChecksumHash(sessionKey.KeyValue, s4uByteArray.Bytes(), keyusage.KERB_NON_KERB_CKSUM_SALT)
	if err != nil {
		log.Errorln(err)
		return
	}

	impersonatedPrinc := types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, impersonate)
	paForUser := types.PAForUser{
		UserName:  impersonatedPrinc,
		UserRealm: userDomain,
		Chksum: types.Checksum{
			CksumType: checksumEtype.GetHashID(),
			Checksum:  cksumHash,
		},
		AuthPackage: "Kerberos",
	}
	paForUserBuf, err := asn1.Marshal(paForUser)
	if err != nil {
		log.Errorf("error marshaling PAForUser: %v", err)
		return
	}
	// Making sure required flags are set
	types.SetFlag(&tgsReq.ReqBody.KDCOptions, flags.Forwardable)
	types.SetFlag(&tgsReq.ReqBody.KDCOptions, flags.Renewable)
	types.SetFlag(&tgsReq.ReqBody.KDCOptions, flags.Canonicalize)
	// Seems like we must support RC4 cipher for S4U
	if !slices.Contains(tgsReq.ReqBody.EType, etypeID.RC4_HMAC) {
		tgsReq.ReqBody.EType = append(tgsReq.ReqBody.EType, etypeID.RC4_HMAC)
	}

	pa := types.PAData{
		PADataType:  patype.PA_FOR_USER,
		PADataValue: paForUserBuf,
	}
	tgsReq.PAData = append(tgsReq.PAData, pa)
	_, tgsRep, err := c.TGSExchange(tgsReq, strings.ToUpper(userDomain), tgt, sessionKey, 0)
	if err != nil {
		log.Errorln(err)
		return
	}
	return tgsRep.Ticket, nil
}

func doS4U2SelfU2U(c *client.Client, conf *config.Config, username, userDomain string, impersonate string, tgt messages.Ticket, sessionKey types.EncryptionKey) (st messages.Ticket, err error) {
	auth, err := types.NewAuthenticator(strings.ToUpper(userDomain), types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, username))
	if err != nil {
		log.Errorln(err)
		return
	}

	apReq, err := messages.NewAPReq(tgt, sessionKey, auth)
	if err != nil {
		log.Errorln(err)
		return
	}
	apReqBytes, err := apReq.Marshal()
	if err != nil {
		log.Errorln(err)
		return
	}

	tgsReq, err := messages.NewS4UTGSReq(types.PrincipalName{}, types.NewPrincipalName(nametype.KRB_NT_UNKNOWN, username), tgt.Realm, conf)
	if err != nil {
		log.Errorln(err)
		return
	}
	tgsReq.PAData = types.PADataSequence{
		types.PAData{
			PADataType:  patype.PA_TGS_REQ,
			PADataValue: apReqBytes,
		},
	}

	//TODO Figure out why RTime cannot be set
	tgsReq.ReqBody.RTime = time.Time{}

	s4uByteArray := bytes.NewBuffer([]byte{})
	binary.Write(s4uByteArray, binary.LittleEndian, nametype.KRB_NT_PRINCIPAL)
	binary.Write(s4uByteArray, binary.LittleEndian, []byte(impersonate+userDomain+"Kerberos"))

	cksumID, err := paForUserChksumType(sessionKey)
	if err != nil {
		log.Errorln(err)
		return
	}
	checksumEtype, err := crypto.GetChksumEtype(cksumID)
	if err != nil {
		log.Errorln(err)
		return
	}
	cksumHash, err := checksumEtype.GetChecksumHash(sessionKey.KeyValue, s4uByteArray.Bytes(), keyusage.KERB_NON_KERB_CKSUM_SALT)
	if err != nil {
		log.Errorln(err)
		return
	}

	impersonatedPrinc := types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, impersonate)
	paForUser := types.PAForUser{
		UserName:  impersonatedPrinc,
		UserRealm: userDomain,
		Chksum: types.Checksum{
			CksumType: checksumEtype.GetHashID(),
			Checksum:  cksumHash,
		},
		AuthPackage: "Kerberos",
	}
	paForUserBuf, err := asn1.Marshal(paForUser)
	if err != nil {
		log.Errorf("error marshaling PAForUser: %v", err)
		return
	}
	// Making sure required flags are set
	types.SetFlag(&tgsReq.ReqBody.KDCOptions, flags.Forwardable)
	types.SetFlag(&tgsReq.ReqBody.KDCOptions, flags.Renewable)
	types.SetFlag(&tgsReq.ReqBody.KDCOptions, flags.Canonicalize)
	types.SetFlag(&tgsReq.ReqBody.KDCOptions, flags.RenewableOK)
	types.SetFlag(&tgsReq.ReqBody.KDCOptions, flags.EncTktInSkey)
	types.UnsetFlag(&tgsReq.ReqBody.KDCOptions, flags.Proxiable)
	// Seems like we must support RC4 cipher for S4U
	tgsReq.ReqBody.EType = []int32{tgt.EncPart.EType, etypeID.RC4_HMAC}

	//tgsReq.ReqBody.RTime = time.Time{}
	pa := types.PAData{
		PADataType:  patype.PA_FOR_USER,
		PADataValue: paForUserBuf,
	}
	tgsReq.PAData = append(tgsReq.PAData, pa)

	tgsReq.ReqBody.AdditionalTickets = append(tgsReq.ReqBody.AdditionalTickets, tgt)

	_, tgsRep, err := c.TGSExchange(tgsReq, strings.ToUpper(userDomain), tgt, sessionKey, 0)
	if err != nil {
		log.Errorln(err)
		return
	}
	return tgsRep.Ticket, nil
}

func getServiceTicket(args *userArgs) (targetSPN string, err error) {
	c := args.c
	conf := args.krbConf
	if args.u2u && args.impersonate != "" {
		// S4U2Self + U2U: combined request, no S4U2Proxy
		var tgt messages.Ticket
		var sessionKey types.EncryptionKey
		tgt, sessionKey, err = c.GetTGT(args.userDomainUpper)
		if err != nil {
			log.Errorln(err)
			return
		}
		log.Infof("Requesting S4U2Self+U2U for %s\n", args.impersonate)
		_, err = doS4U2SelfU2U(c, conf, args.username, args.userDomain, args.impersonate, tgt, sessionKey)
		if err != nil {
			log.Errorln(err)
			return
		}
		targetSPN = args.username
	} else if args.u2u && args.additionalTicketFile != "" {
		// Plain U2U: use target's TGT from file
		log.Infof("Requesting plain U2U ticket for %s\n", args.spn)
		targetSPN, err = doPlainU2U(args)
		if err != nil {
			log.Errorln(err)
			return
		}
	} else if args.impersonate != "" {
		var tgt, st messages.Ticket
		var sessionKey types.EncryptionKey
		tgt, sessionKey, err = c.GetTGT(args.userDomainUpper)
		if err != nil {
			log.Errorln(err)
			return
		}
		st, err = doS4U2Self(c, conf, args.username, args.userDomain, args.impersonate, tgt, sessionKey)
		if err != nil {
			log.Errorln(err)
			return
		}
		err = doS4U2Proxy(c, conf, args.username, args.userDomain, args.impersonate, tgt, st, sessionKey, args.spn)
		if err != nil {
			log.Errorln(err)
			return
		}
		targetSPN = args.spn
	} else {
		targetSPN, err = requestServiceTicket(args)
	}
	return
}

func requestServiceTicket(args *userArgs) (targetSPN string, err error) {
	// Always pass the SPN as-is to the KDC. The KDC is authoritative for
	// resolving the SPN — we should not rewrite it based on domain guessing.
	targetSPN = args.spn
	log.Infof("Trying to get a service ticket for target SPN: %s and dcDomain: %s\n", targetSPN, args.dcDomain)
	tkt, _, err := args.c.GetServiceTicketExt(targetSPN, args.dcDomain)
	if err != nil {
		log.Errorln(err)
		return
	}
	if args.inspect {
		err = inspectTicket(&tkt, args.signingKey, args.signAes)
		if err != nil {
			log.Errorln(err)
			//return
		}
	}
	return
}

func loadTicketFromFile(path string) (ticket messages.Ticket, err error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return ticket, fmt.Errorf("failed to read ticket file %s: %v", path, err)
	}
	if len(data) < 1 {
		return ticket, fmt.Errorf("ticket file %s is empty", path)
	}
	switch data[0] {
	case 0x76:
		// Kirbi format
		cred, err := fromKirbi(data)
		if err != nil {
			return ticket, fmt.Errorf("failed to parse kirbi file: %v", err)
		}
		err = ticket.Unmarshal(cred.Ticket)
		if err != nil {
			return ticket, fmt.Errorf("failed to unmarshal ticket from kirbi: %v", err)
		}
	case 0x05:
		// CCache format
		cache := new(credentials.CCache)
		err = cache.Unmarshal(data)
		if err != nil {
			return ticket, fmt.Errorf("failed to parse ccache file: %v", err)
		}
		entries := cache.GetEntries()
		if len(entries) < 1 {
			return ticket, fmt.Errorf("ccache file contains no tickets")
		}
		// Use the first entry's ticket
		err = ticket.Unmarshal(entries[0].Ticket)
		if err != nil {
			return ticket, fmt.Errorf("failed to unmarshal ticket from ccache: %v", err)
		}
	default:
		return ticket, fmt.Errorf("unknown ticket file format (first byte: 0x%02x), expected ccache (0x05) or kirbi (0x76)", data[0])
	}
	return
}

func doPlainU2U(args *userArgs) (targetSPN string, err error) {
	c := args.c
	conf := args.krbConf
	targetSPN = args.spn

	// Load target's TGT from file
	targetTGT, err := loadTicketFromFile(args.additionalTicketFile)
	if err != nil {
		return
	}
	log.Infof("Loaded target TGT from %s\n", args.additionalTicketFile)

	// Get our own TGT and session key
	tgt, sessionKey, err := c.GetTGT(args.userDomainUpper)
	if err != nil {
		return
	}

	// Build U2U TGS-REQ with target's TGT as additional ticket. The target
	// for plain U2U is a user principal — encode it with the AD-canonical
	// name type derived from the --spn form (KRB_NT_ENTERPRISE for UPN /
	// sAMAccountName, KRB_NT_SRV_INST if a service-style SPN was given).
	sname := types.NewPrincipalName(args.serviceNameType, args.spn)
	tgsReq, err := messages.NewUser2UserTGSReq(
		c.Credentials.CName(),
		args.userDomainUpper,
		conf,
		tgt,
		sessionKey,
		sname,
		false,
		targetTGT,
	)
	if err != nil {
		return
	}

	_, _, err = c.TGSExchange(tgsReq, args.userDomainUpper, tgt, sessionKey, 0)
	if err != nil {
		return
	}

	return
}
