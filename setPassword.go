// MIT License
//
// # Copyright (c) 2026 Jimmy Fjällid
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

	"golang.org/x/term"
)

var helpSetPasswordOptions = `
    Usage: ` + os.Args[0] + ` --set-password [options]

    Change your own password or, with --target-user, reset another account's
    password over the Kerberos kpasswd protocol (RFC 3244, port 464).

    Without --target-user the authenticating account's own password is changed
    (works even if the current password is expired). With --target-user the
    authenticating account resets the named account's password and therefore
    must hold reset privileges over it.
    ` + helpConnectionOptions + `
    options:
          --new-pass <password>   New password to set. Prompted for (with
                                  confirmation) if omitted.
          --target-user <name>    Account to reset. Omit to change your own
                                  password.
          --krb5-conf <file>      Read krb5.conf file and use as config
`

func handleSetPassword(args *userArgs) (err error) {
	if args.newPassword == "" {
		args.newPassword, err = promptNewPassword()
		if err != nil {
			return err
		}
	}

	var ok bool
	if args.targetUsername == "" {
		ok, err = args.c.ChangePasswd(args.newPassword)
	} else {
		ok, err = args.c.SetPasswd(args.targetUsername, args.userDomainUpper, args.newPassword)
	}
	if err != nil {
		log.Errorln(err)
		return err
	}
	if !ok {
		return fmt.Errorf("kpasswd did not report success")
	}

	if !args.quiet {
		if args.targetUsername == "" {
			fmt.Printf("Successfully changed password for %s@%s\n", args.username, args.userDomainUpper)
		} else {
			fmt.Printf("Successfully reset password for %s@%s\n", args.targetUsername, args.userDomainUpper)
		}
	}
	return nil
}

// promptNewPassword reads the new password twice from the terminal without
// echoing and requires the two entries to match.
func promptNewPassword() (string, error) {
	fmt.Printf("New password: ")
	first, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()
	if err != nil {
		return "", err
	}
	fmt.Printf("Confirm new password: ")
	second, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()
	if err != nil {
		return "", err
	}
	if string(first) != string(second) {
		return "", fmt.Errorf("passwords do not match")
	}
	if len(first) == 0 {
		return "", fmt.Errorf("new password must not be empty")
	}
	return string(first), nil
}
