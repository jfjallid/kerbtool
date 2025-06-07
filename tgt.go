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
          --krb5-conf <file>      Read krb5.conf file and use as config
`

func handleAskTGT(args *userArgs) (err error) {
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

	// Verify that we have a TGT in the cache or request one
	_, _, err = args.c.GetTGT(args.userDomainUpper)
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

	err = saveToCCACHE(args, nil, nil, "krbtgt/"+args.userDomainUpper, args.dumpAllTickets)
	if err != nil {
		log.Errorln(err)
		return
	}

	return
}
