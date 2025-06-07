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
	"fmt"
	"os"
	"strings"
	"time"

	"encoding/base64"
	"github.com/jfjallid/gokrb5/v8/credentials"
	"github.com/jfjallid/gokrb5/v8/krberror"
	"github.com/jfjallid/gokrb5/v8/messages"
	"github.com/jfjallid/gokrb5/v8/types"
)

var helpConvertTicketOptions = `
    Usage: ` + os.Args[0] + ` --convert [options]
    options:
          --in <file>             Path to ticket file to convert from CCACHE/Kirbi
          --out <file>            Path to save converted ticket file. Skip to get output as B64
          --ticket <b64>          B64 string of ticket to convert. Mutually exclusive with --in
    ` + helpGeneralOptions + `
`

func handleConvertTicket(args *userArgs) (err error) {
	if args.inputFilename != "" && args.ticketB64 != "" {
		fmt.Println("Arguments --in and --ticket are mutually excusive. Choose ONE")
		myFlags.Usage()
	}
	if args.inputFilename == "" && args.ticketB64 == "" {
		fmt.Println("Must specify a ticket to convert. Either with --in or --ticket")
		myFlags.Usage()
	}
	var input, output []byte
	var srcFormat, dstFormat string
	if args.inputFilename != "" {
		input, err = os.ReadFile(args.inputFilename)
		if err != nil {
			log.Errorln(err)
			return
		}
	} else {
		input, err = base64.StdEncoding.DecodeString(args.ticketB64)
		if err != nil {
			log.Errorln(err)
			return
		}
	}
	if len(input) == 0 {
		err = fmt.Errorf("Cannot convert an empty file!")
		return
	}
	switch input[0] {
	case 0x76:
		// Kirbi
		srcFormat = "kirbi"
		dstFormat = "ccache"
		var cred *credentials.Credential
		cred, err = fromKirbi(input)
		if err != nil {
			log.Errorln(err)
			return
		}
		cache := credentials.NewV4CCache()
		cache.SetKDCTimeOffset(0xFFFFFFFF, 0) // TODO Any better value here?
		cache.SetDefaultPrincipal(cred.Client)
		cache.AddCredential(cred)
		output, err = cache.Marshal()
		if err != nil {
			log.Errorln(err)
			return
		}
	case 0x5:
		// CCACHE
		srcFormat = "ccache"
		dstFormat = "kirbi"
		cache := new(credentials.CCache)
		err = cache.Unmarshal(input)
		if err != nil {
			log.Errorln(err)
			return
		}
		entries := cache.GetEntries()
		if len(entries) < 1 {
			return fmt.Errorf("CCACHE is empty!")
		}
		if len(entries) > 1 {
			log.Notice("CCACHE file contains multiple tickets. Only first one is converted")
		}
		var krbCred *messages.KRBCred
		krbCred, err = toKRBCred(entries[0])
		if err != nil {
			log.Errorln(err)
			return
		}
		output, err = krbCred.Marshal()
		if err != nil {
			log.Errorln(err)
			return
		}
	default:
		return fmt.Errorf("Unknown ticket file type")
	}
	if args.outputFilename == "" {
		fmt.Printf("Ticket converted from %s to %s with base64 encoding:\n%s\n", srcFormat, dstFormat, base64.StdEncoding.EncodeToString([]byte(output)))
		return
	} else {
		var f *os.File
		f, err = os.OpenFile(args.outputFilename, os.O_CREATE|os.O_TRUNC|os.O_RDWR, 0600)
		if err != nil {
			log.Errorln(err)
			return
		}
		defer f.Close()

		_, err = f.Write(output)
		if err != nil {
			log.Errorln(err)
			return
		}
		fmt.Printf("Ticket converted from %s to %s!\n", srcFormat, dstFormat)
	}
	return
}

func isKirbi(r *bytes.Reader) (bool, error) {
	b := make([]byte, 1)
	_, err := r.ReadAt(b, 0)
	if err != nil {
		log.Errorln(err)
		return false, err
	}
	return b[0] == 0x76, nil
}

func isCcache(r *bytes.Reader) (bool, error) {
	b := make([]byte, 1)
	_, err := r.ReadAt(b, 0)
	if err != nil {
		log.Errorln(err)
		return false, err
	}
	return b[0] == 0x5, nil
}

func toKRBCred(c *credentials.Credential) (krbCred *messages.KRBCred, err error) {
	if c == nil {
		err = fmt.Errorf("Cannot convert a nil credential")
		log.Errorln(err)
		return
	}

	krbCredInfo := messages.KrbCredInfo{}
	krbCredInfo.Key.KeyType = c.Key.KeyType
	krbCredInfo.Key.KeyValue = make([]byte, len(c.Key.KeyValue))
	copy(krbCredInfo.Key.KeyValue, c.Key.KeyValue)

	krbCredInfo.PRealm = strings.Clone(c.Client.Realm)

	krbCredInfo.PName.NameType = c.Client.PrincipalName.NameType
	for _, s := range c.Client.PrincipalName.NameString {
		krbCredInfo.PName.NameString = append(krbCredInfo.PName.NameString, strings.Clone(s))
	}

	krbCredInfo.Flags = types.NewKrbFlags()
	copy(krbCredInfo.Flags.Bytes, c.TicketFlags.Bytes)

	krbCredInfo.AuthTime = time.Unix(0, c.AuthTime.UTC().UnixNano()).UTC()
	krbCredInfo.StartTime = time.Unix(0, c.StartTime.UTC().UnixNano()).UTC()
	krbCredInfo.EndTime = time.Unix(0, c.EndTime.UTC().UnixNano()).UTC()
	krbCredInfo.RenewTill = time.Unix(0, c.RenewTill.UTC().UnixNano()).UTC()

	krbCredInfo.SRealm = strings.Clone(c.Server.Realm)

	krbCredInfo.SName.NameType = c.Server.PrincipalName.NameType
	for _, s := range c.Server.PrincipalName.NameString {
		krbCredInfo.SName.NameString = append(krbCredInfo.SName.NameString, strings.Clone(s))
	}

	encKrbCredPart := messages.EncKrbCredPart{
		TicketInfo: []messages.KrbCredInfo{krbCredInfo},
	}
	krbCred = &messages.KRBCred{
		PVNO:             5,
		MsgType:          22,
		DecryptedEncPart: encKrbCredPart,
	}

	var t messages.Ticket
	err = t.Unmarshal(c.Ticket)
	if err != nil {
		log.Errorln(err)
		return
	}
	krbCred.Tickets = []messages.Ticket{t}
	return
}

func fromKRBCred(krbCred *messages.KRBCred) (c *credentials.Credential, err error) {
	if len(krbCred.DecryptedEncPart.TicketInfo) < 1 {
		err = fmt.Errorf("KRBCred did not contain any TicketInfo!")
		return
	}
	if len(krbCred.Tickets) < 1 {
		err = fmt.Errorf("KRBCred did not contain any Tickets!")
		return
	}
	if len(krbCred.Tickets) > 1 {
		log.Noticeln("KRBCred contains multiple tickets but only converting the first")
	}
	c = &credentials.Credential{}
	krbCredInfo := krbCred.DecryptedEncPart.TicketInfo[0]

	c.Key.KeyType = krbCredInfo.Key.KeyType
	c.Key.KeyValue = make([]byte, len(krbCredInfo.Key.KeyValue))
	copy(c.Key.KeyValue, krbCredInfo.Key.KeyValue)

	c.Client.Realm = strings.Clone(krbCredInfo.PRealm)

	c.Client.PrincipalName.NameType = krbCredInfo.PName.NameType
	for _, s := range krbCredInfo.PName.NameString {
		c.Client.PrincipalName.NameString = append(c.Client.PrincipalName.NameString, strings.Clone(s))
	}

	c.TicketFlags = types.NewKrbFlags()
	copy(c.TicketFlags.Bytes, krbCredInfo.Flags.Bytes)

	c.AuthTime = time.Unix(0, krbCredInfo.AuthTime.UTC().UnixNano()).UTC()
	c.StartTime = time.Unix(0, krbCredInfo.StartTime.UTC().UnixNano()).UTC()
	c.EndTime = time.Unix(0, krbCredInfo.EndTime.UTC().UnixNano()).UTC()
	c.RenewTill = time.Unix(0, krbCredInfo.RenewTill.UTC().UnixNano()).UTC()

	c.Server.Realm = strings.Clone(krbCredInfo.SRealm)

	c.Server.PrincipalName.NameType = krbCredInfo.SName.NameType
	for _, s := range krbCredInfo.SName.NameString {
		c.Server.PrincipalName.NameString = append(c.Server.PrincipalName.NameString, strings.Clone(s))
	}

	c.Ticket, err = krbCred.Tickets[0].Marshal()
	if err != nil {
		log.Errorln(err)
		return
	}
	//TODO What about potential ClientAddresses?

	return
}

func fromKirbi(data []byte) (c *credentials.Credential, err error) {
	var krbCred messages.KRBCred
	err = krbCred.Unmarshal(data)
	if err != nil {
		log.Errorln(err)
		return
	}
	if krbCred.EncPart.EType != 0 {
		err = fmt.Errorf("Support for decrypting Kirbi EncPart not supported for EType: %d", krbCred.EncPart.EType)
		return
	}
	var denc messages.EncKrbCredPart
	err = denc.Unmarshal(krbCred.EncPart.Cipher)
	if err != nil {
		err = krberror.Errorf(err, krberror.EncodingError, "error unmarshaling encrypted part of KRB_CRED")
		return
	}
	krbCred.DecryptedEncPart = denc
	c, err = fromKRBCred(&krbCred)
	if err != nil {
		log.Errorln(err)
		return
	}
	return
}
