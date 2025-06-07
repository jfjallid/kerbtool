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
	"fmt"
	"os"

	"github.com/jfjallid/gofork/encoding/asn1"
	"github.com/jfjallid/gokrb5/v8/credentials"
	"github.com/jfjallid/gokrb5/v8/crypto"
	"github.com/jfjallid/gokrb5/v8/iana/adtype"
	"github.com/jfjallid/gokrb5/v8/iana/etypeID"
	"github.com/jfjallid/gokrb5/v8/iana/flags"
	"github.com/jfjallid/gokrb5/v8/messages"
	"github.com/jfjallid/gokrb5/v8/pac"
	"github.com/jfjallid/gokrb5/v8/types"
)

var helpParseTicketOptions = `
    Usage: ` + os.Args[0] + ` --parse [options]
    ` + helpConnectionOptions + `
    options:
          --sign-nt <NT Hash>     Hex encoded NT Hash of key to decrypt ticket with
          --sign-aes <AES key>    Hex encoded AES128/256 key to decrypt ticket with
          --ticket <hex>          Hex encoded ticket bytes to inspect
          --in <file>             File with ticket in ccache or kirbi format
`

func handleParseTicket(args *userArgs) (err error) {

	if len(args.ticketBytes) == 0 && args.inputFilename == "" {
		return fmt.Errorf("Must specify either a hex encoded ticket to inspect with --ticket or a file with --in")
	}
	if len(args.ticketBytes) > 0 && args.inputFilename != "" {
		return fmt.Errorf("Choose ONE of --ticket --in with content to inspect")
	}
	if args.signKeyNT != nil && args.signKeyAES != nil {
		return fmt.Errorf("Choose ONE of --sign-nt and --sign-aes when inspecting tickets")
	}
	if args.signKeyNT == nil && args.signKeyAES == nil {
		return fmt.Errorf("Must provide a decryption key with either --sign-nt or --sign-aes when inspecting a ticket")
	}
	if args.signKeyNT != nil && (len(args.signKeyNT) != 16) {
		return fmt.Errorf("Invalid length of NT hash provided with --sign-nt argument")
	}
	if args.signKeyAES != nil {
		hashLen := len(args.signKeyAES)
		switch hashLen {
		case 16:
			args.signAes = true
			args.signingKey = args.signKeyAES
		case 32:
			args.signingKey = args.signKeyAES
			args.signAes = true
		default:
			return fmt.Errorf("Invalid length of hex for --sign-aes: %d\n", hashLen)
		}
	} else {
		args.signingKey = args.signKeyNT
	}

	if len(args.ticketBytes) > 0 {
		err = inspectTicketBytes(args.ticketBytes, args.signingKey, args.signAes)
		if err != nil {
			log.Errorln(err)
		}
	} else {
		var input []byte
		input, err = os.ReadFile(args.inputFilename)
		if err != nil {
			log.Errorln(err)
			return
		}
		if len(input) == 0 {
			err = fmt.Errorf("Cannot inspect an empty file!")
			return
		}
		switch input[0] {
		case 0x76:
			// Kirbi
			log.Infoln("Identified file as a KIRBI file")
			var cred *credentials.Credential
			cred, err = fromKirbi(input)
			if err != nil {
				log.Errorln(err)
				return
			}
			err = inspectTicketBytes(cred.Ticket, args.signingKey, args.signAes)
			if err != nil {
				log.Errorln(err)
				return
			}
		case 0x5:
			// CCACHE
			log.Infoln("Identified file as a CCACHE")
			cache := new(credentials.CCache)
			err = cache.Unmarshal(input)
			if err != nil {
				log.Errorln(err)
				return
			}
			entries := cache.GetEntries()
			numEntries := len(entries)
			log.Infof("Parsed ccache file and found %d item(s)\n", numEntries)
			if numEntries < 1 {
				return fmt.Errorf("CCACHE is empty!")
			}
			if numEntries > 1 {
				log.Notice("CCACHE file contains multiple tickets. Only first one is inspected")
			}
			err = inspectTicketBytes(entries[0].Ticket, args.signingKey, args.signAes)
			if err != nil {
				log.Errorln(err)
				return
			}
		}
	}
	return
}

func inspectTicketBytes(cipher []byte, key []byte, isAesKey bool) (err error) {
	var ticket = &messages.Ticket{}
	ticket.Unmarshal(cipher)
	// Maybe below is needed for some cases?
	//_, err = asn1.Unmarshal(cipher, ticket)
	//if err != nil {
	//	log.Errorln(err)
	//	return
	//}
	err = inspectTicket(ticket, key, isAesKey)
	if err != nil {
		log.Errorln(err)
		return
	}
	return
}

func inspectTicket(ticket *messages.Ticket, key []byte, isAesKey bool) (err error) {
	decryptionKey, err := decryptTicket(ticket, key, isAesKey)
	if err != nil {
		log.Errorln(err)
		return
	}
	return inspectDecryptedTicket(ticket, decryptionKey)
}

func inspectDecryptedTicket(ticket *messages.Ticket, decryptionKey types.EncryptionKey) (err error) {
	ticketFlags := parseTicketFlags(ticket.DecryptedEncPart.Flags)
	fmt.Println("Ticket content:")
	fmt.Printf("TktVNO: %d\n", ticket.TktVNO)
	fmt.Printf("Realm: %s\n", ticket.Realm)
	fmt.Printf("SName: (type: %d, name: %s)\n", ticket.SName.NameType, ticket.SName.PrincipalNameString())
	fmt.Println("Ticket encrypted part:")
	fmt.Printf("  Flags: %v\n", ticketFlags)
	fmt.Printf("  CRealm: %s\n", ticket.DecryptedEncPart.CRealm)
	fmt.Printf("  CName: %s\n", ticket.DecryptedEncPart.CName.PrincipalNameString())
	fmt.Printf("  CName: (type: %d, name: %s)\n", ticket.DecryptedEncPart.CName.NameType, ticket.DecryptedEncPart.CName.PrincipalNameString())
	fmt.Printf("  AuthTime: %s\n", ticket.DecryptedEncPart.AuthTime)
	fmt.Printf("  StartTime: %s\n", ticket.DecryptedEncPart.StartTime)
	fmt.Printf("  EndTime: %s\n", ticket.DecryptedEncPart.EndTime)
	fmt.Printf("  RenewTill: %s\n", ticket.DecryptedEncPart.RenewTill)
	fmt.Printf("  CAddr: %+v\n", ticket.DecryptedEncPart.CAddr)

	fmt.Println("  AuthorizationData:")
	for _, ad := range ticket.DecryptedEncPart.AuthorizationData {
		if ad.ADType == adtype.ADIfRelevant {
			fmt.Printf("  AuthorizationData[0].ADType: ADIfRelevant\n")
			var ad2 types.AuthorizationData
			err = ad2.Unmarshal(ad.ADData)
			if err != nil {
				log.Errorf("PAC authorization data could not be unmarshaled: %v", err)
				continue
			}
			if ad2[0].ADType == adtype.ADWin2KPAC {
				fmt.Printf("  AuthorizationData[0].ADData[0].ADType: ADWin2KPAC\n")
				var p pac.PACType
				err = p.Unmarshal(ad2[0].ADData)
				if err != nil {
					log.Errorf("error: %s\n", err)
					return
				}

				err = p.ProcessPACInfoBuffers(decryptionKey, log.Logger(), true)
				if err != nil {
					log.Errorf("error: %s\n", err)
					//return
				}
				fmt.Println("### PAC ###")
				fmt.Printf("PAC.CBuffers: %d\n", p.CBuffers)
				fmt.Printf("PAC.Version: %d\n", p.Version)
				inspectKerbValidationInfo(p.KerbValidationInfo)
				fmt.Printf("\n### ClientInfo ###\n")
				fmt.Printf("ClientID: %s\n", p.ClientInfo.ClientID.Time())
				fmt.Printf("NameLength: %d\n", p.ClientInfo.NameLength)
				fmt.Printf("Name: %s\n", p.ClientInfo.Name)

				fmt.Printf("\n### ClientClaims ###\n%+v\n", p.ClientClaimsInfo)

				fmt.Printf("\n### ServerChecksum ###\n")
				fmt.Printf("SignatureType: %d\n", p.ServerChecksum.SignatureType)
				fmt.Printf("Signature: %x\n", p.ServerChecksum.Signature)
				fmt.Printf("RODCIdentifier: %d\n", p.ServerChecksum.RODCIdentifier)

				fmt.Printf("\n### KDCChecksum ###\n")
				fmt.Printf("SignatureType: %d\n", p.KDCChecksum.SignatureType)
				fmt.Printf("Signature: %x\n", p.KDCChecksum.Signature)
				fmt.Printf("RODCIdentifier: %d\n", p.KDCChecksum.RODCIdentifier)

				fmt.Printf("\n### UPNDNSInfo ###\n%+v\n", p.UPNDNSInfo)
				fmt.Printf("\n### PacAttributesInfo ###\n%+v\n", p.PacAttributesInfo)
				fmt.Printf("\n### PacRequestorSid ###\n%+v\n", p.PacRequestorSid)
				fmt.Printf("\n### CredentialsInfo ###\n%+v\n", p.CredentialsInfo)
				fmt.Printf("\n### S4UDelegationInfo ###\n%+v\n", p.S4UDelegationInfo)
				fmt.Printf("\n### DeviceInfo ###\n%+v\n", p.DeviceInfo)
				fmt.Printf("\n### DeviceClaimsInfo ###\n%+v\n", p.DeviceClaimsInfo)

				fmt.Println()
			}
		}
	}
	return
}

func inspectKerbValidationInfo(k *pac.KerbValidationInfo) {
	fmt.Println("\n### KerbValidationInfo ###")
	fmt.Printf("LogOnTime: %s\n", k.LogOnTime.Time())
	fmt.Printf("LogOffTime: %s\n", k.LogOffTime.Time())
	fmt.Printf("KickOffTime: %s\n", k.KickOffTime.Time())
	fmt.Printf("PasswordLastSet: %s\n", k.PasswordLastSet.Time())
	fmt.Printf("PasswordCanChange: %s\n", k.PasswordCanChange.Time())
	fmt.Printf("PasswordMustChange: %s\n", k.PasswordMustChange.Time())
	fmt.Printf("EffectiveName: %s\n", k.EffectiveName.Value)
	fmt.Printf("FullName: %s\n", k.FullName.Value)
	fmt.Printf("LogonScript: %s\n", k.LogonScript.Value)
	fmt.Printf("ProfilePath: %s\n", k.ProfilePath.Value)
	fmt.Printf("HomeDirectory: %s\n", k.HomeDirectory.Value)
	fmt.Printf("HomeDirectoryDrive: %s\n", k.HomeDirectoryDrive.Value)
	fmt.Printf("LogonCount: %d\n", k.LogonCount)
	fmt.Printf("BadPasswordCount: %d\n", k.BadPasswordCount)
	fmt.Printf("UserID: %d\n", k.UserID)
	fmt.Printf("PrimaryGroupID: %d\n", k.PrimaryGroupID)
	fmt.Printf("GroupCount: %d\n", k.GroupCount)
	fmt.Printf("GroupIDs: %+v\n", k.GroupIDs)
	fmt.Printf("UserFlags: %d\n", k.UserFlags)
	fmt.Printf("UserSessionKey: %+v\n", k.UserSessionKey)
	fmt.Printf("LogonServer: %s\n", k.LogonServer.Value)
	fmt.Printf("LogonDomainName: %s\n", k.LogonDomainName.Value)
	fmt.Printf("LogonDomainID: %+v\n", k.LogonDomainID)
	fmt.Printf("UserAccountControl: %d\n", k.UserAccountControl)
	fmt.Printf("SubAuthStatus: %d\n", k.SubAuthStatus)
	fmt.Printf("LastSuccessfulILogon: %s\n", k.LastSuccessfulILogon.Time())
	fmt.Printf("LastFailedILogon: %s\n", k.LastFailedILogon.Time())
	fmt.Printf("FailedILogonCount: %d\n", k.FailedILogonCount)
	fmt.Printf("SIDCount: %d\n", k.SIDCount)
	fmt.Printf("ExtraSIDs: %+v\n", k.ExtraSIDs)
	fmt.Printf("ResourceGroupDomainSID: %+v\n", k.ResourceGroupDomainSID)
	fmt.Printf("ResourceGroupCount: %d\n", k.ResourceGroupCount)
	fmt.Printf("ResourceGroupIDs: %+v\n", k.ResourceGroupIDs)
}

func getPac(ad *types.AuthorizationData, decryptionKey types.EncryptionKey) (p *pac.PACType, err error) {
	p = &pac.PACType{}
	for _, ad2 := range *ad {
		if ad2.ADType == adtype.ADIfRelevant {
			var ad3 types.AuthorizationData
			err = ad3.Unmarshal(ad2.ADData)
			if err != nil {
				return
			}
			if ad3[0].ADType == adtype.ADWin2KPAC {
				err = p.Unmarshal(ad3[0].ADData)
				if err != nil {
					return
				}
				err = p.ProcessPACInfoBuffers(decryptionKey, log.Logger(), true)
				if err != nil {
					return
				}
				p.Buffers = nil
				p.Data = nil
				p.ZeroSigData = nil
				return
			}
		} else {
			fmt.Printf("Found more in ad: %v\n", ad2.ADType)
		}
	}
	return nil, fmt.Errorf("Did not find a PAC!")
}

func decryptTicket2(ticket *messages.Ticket, key types.EncryptionKey) (decryptionKey types.EncryptionKey, err error) {
	isAesKey := false
	switch key.KeyType {
	case etypeID.AES256_CTS_HMAC_SHA1_96, etypeID.AES128_CTS_HMAC_SHA1_96:
		isAesKey = true
	case etypeID.RC4_HMAC:
	default:
		err = fmt.Errorf("Unknown decryption key type: %d", key.KeyType)
		return
	}
	return decryptTicket(ticket, key.KeyValue, isAesKey)
}
func decryptTicket(ticket *messages.Ticket, key []byte, isAesKey bool) (decryptionKey types.EncryptionKey, err error) {
	ticketEid := ticket.EncPart.EType
	ticketEtype := ""
	switch ticketEid {
	case etypeID.RC4_HMAC:
		ticketEtype = "RC4_HMAC"
	case etypeID.AES128_CTS_HMAC_SHA1_96:
		ticketEtype = "AES128_CTS_HMAC_SHA1_96"
	case etypeID.AES256_CTS_HMAC_SHA1_96:
		ticketEtype = "AES256_CTS_HMAC_SHA1_96"
	default:
		ticketEtype = "UNKNOWN"
	}
	var eid int32
	if !isAesKey && len(key) == 16 {
		eid = etypeID.RC4_HMAC
	} else if isAesKey && len(key) == 16 {
		eid = etypeID.AES128_CTS_HMAC_SHA1_96
	} else if isAesKey && len(key) == 32 {
		eid = etypeID.AES256_CTS_HMAC_SHA1_96
	} else {
		err = fmt.Errorf("Unknown key type of len: %d with isAesKey: %v\n", len(key), isAesKey)
		log.Errorln(err)
		return
	}
	if eid != ticketEid {
		err = fmt.Errorf("Wrong type of encryption key provided. Ticket is encrypted using a %s key\n", ticketEtype)
		return
	}
	decryptionKey, _, err = crypto.GetKeyFromHash(key, types.PrincipalName{}, "", eid, types.PADataSequence{})
	if err != nil {
		log.Errorf("error getting decryption key: %s\n", err)
		return
	}
	fmt.Printf("Decrypting ticket with a keytype: %d, key: %x\n", eid, decryptionKey.KeyValue)
	err = ticket.Decrypt(decryptionKey)
	if err != nil {
		log.Errorf("Wrong decryption key? %s\n", err)
		return
	}
	return
}

func parseTicketFlags(ticketFlags asn1.BitString) (res []string) {
	if types.IsFlagSet(&ticketFlags, flags.Forwardable) {
		res = append(res, "Forwardable")
	}
	if types.IsFlagSet(&ticketFlags, flags.Forwarded) {
		res = append(res, "Forwarded")
	}
	if types.IsFlagSet(&ticketFlags, flags.Proxiable) {
		res = append(res, "Proxiable")
	}
	if types.IsFlagSet(&ticketFlags, flags.Proxy) {
		res = append(res, "Proxy")
	}
	if types.IsFlagSet(&ticketFlags, flags.AllowPostDate) {
		res = append(res, "AllowPostDate")
	}
	if types.IsFlagSet(&ticketFlags, flags.MayPostDate) {
		res = append(res, "MayPostDate")
	}
	if types.IsFlagSet(&ticketFlags, flags.PostDated) {
		res = append(res, "PostDated")
	}
	if types.IsFlagSet(&ticketFlags, flags.Invalid) {
		res = append(res, "Invalid")
	}
	if types.IsFlagSet(&ticketFlags, flags.Renewable) {
		res = append(res, "Renewable")
	}
	if types.IsFlagSet(&ticketFlags, flags.Initial) {
		res = append(res, "Initial")
	}
	if types.IsFlagSet(&ticketFlags, flags.PreAuthent) {
		res = append(res, "PreAuthent")
	}
	if types.IsFlagSet(&ticketFlags, flags.HWAuthent) {
		res = append(res, "HWAuthent")
	}
	if types.IsFlagSet(&ticketFlags, flags.OptHardwareAuth) {
		res = append(res, "OptHardwareAuth")
	}
	if types.IsFlagSet(&ticketFlags, flags.RequestAnonymous) {
		res = append(res, "RequestAnonymous")
	}
	if types.IsFlagSet(&ticketFlags, flags.TransitedPolicyChecked) {
		res = append(res, "TransitedPolicyChecked")
	}
	if types.IsFlagSet(&ticketFlags, flags.OKAsDelegate) {
		res = append(res, "OKAsDelegate")
	}
	if types.IsFlagSet(&ticketFlags, flags.EncPARep) {
		res = append(res, "EncPARep")
	}
	if types.IsFlagSet(&ticketFlags, flags.Canonicalize) {
		res = append(res, "Canonicalize")
	}
	if types.IsFlagSet(&ticketFlags, flags.DisableTransitedCheck) {
		res = append(res, "DisableTransitedCheck")
	}
	if types.IsFlagSet(&ticketFlags, flags.RenewableOK) {
		res = append(res, "RenewableOK")
	}
	if types.IsFlagSet(&ticketFlags, flags.EncTktInSkey) {
		res = append(res, "EncTktInSkey")
	}
	if types.IsFlagSet(&ticketFlags, flags.Renew) {
		res = append(res, "Renew")
	}
	if types.IsFlagSet(&ticketFlags, flags.Validate) {
		res = append(res, "Validate")
	}
	return
}
