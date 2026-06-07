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
	"encoding/binary"
	"fmt"
	"os"
	"strings"
	"time"
	"unicode/utf16"

	"github.com/jfjallid/gokrb5/v9/crypto"
	"github.com/jfjallid/gokrb5/v9/iana/etypeID"
	"github.com/jfjallid/gokrb5/v9/iana/nametype"
	"github.com/jfjallid/gokrb5/v9/iana/patype"
	"github.com/jfjallid/gokrb5/v9/keytab"
	"github.com/jfjallid/gokrb5/v9/types"

	"golang.org/x/crypto/md4"
)

var helpKeytabOptions = `
    Usage: ` + os.Args[0] + ` --keytab [options]

    Operations (choose one; --list is the default):
          --create                Create a new empty keytab (refuses to overwrite --file)
          --list                  List the entries in the keytab
          --add                   Add entries from the provided key material
          --remove                Remove entries matching --principal/--realm
          --replace               Remove matching entries for the principal, then add new ones
          --update-kvno           Set the kvno of matching entries to --kvno

    options:
          --file <path>           Keytab file to operate on (required)
          --principal <name>      Principal, e.g. host/srv.dom.com or Administrator
          --realm <REALM>         Realm for the principal (uppercased)
          --salt <salt>           Override the salt used for --kt-pass derivation
                                  (default is the realm+principal derivation)
          --kt-pass <password>    Derive key(s) from a password
          --kt-pass-hex <hex>     Derive key(s) from a UTF-16LE password blob given as hex,
                                  e.g. an AD machine account password. RC4 uses MD4 of the
                                  bytes; AES uses the UTF-8 form. Pair with --salt or
                                  --query-salt for the correct (non-default) machine salt
          --kt-hash <hex>         NT hash (RC4 / etype 23) key
          --kt-aes128 <hex>       AES128 (etype 17) key
          --kt-aes256 <hex>       AES256 (etype 18) key
          --enctype <list>        Comma-separated enctypes to derive from --kt-pass (default
                                  aes256-cts-hmac-sha1-96,aes128-cts-hmac-sha1-96,rc4-hmac);
                                  for --remove/--update-kvno an optional single-enctype filter
          --kvno <n>              Key version number to assign (default 1)
          --match-kvno <n>        Only match entries with this kvno (remove/replace/update-kvno)
          --query-salt            Fetch the account salt from the KDC for --kt-pass derivation
                                  (requires -d/--domain and KDC connectivity)
      ` + helpConnectionOptions + `
`

var defaultKeytabEnctypes = []string{
	"aes256-cts-hmac-sha1-96",
	"aes128-cts-hmac-sha1-96",
	"rc4-hmac",
}

// ktUsage logs an argument error and prints the --keytab usage message. The
// configured Usage handler (see handleArgs) exits the process, so this does not
// return to the caller.
func ktUsage(format string, a ...any) {
	log.Errorf(format+"\n", a...)
	myFlags.Usage()
}

func handleKeytab(args *userArgs) (err error) {
	// When creating a keytab without an explicit --file, default the filename to
	// <principal>.keytab (slashes in SPNs become underscores so it's a valid name).
	if args.ktFile == "" && args.ktCreate && args.ktPrincipal != "" {
		args.ktFile = strings.ReplaceAll(args.ktPrincipal, "/", "_") + ".keytab"
		log.Infof("No --file specified; defaulting to %s\n", args.ktFile)
	}
	if args.ktFile == "" {
		ktUsage("Must specify the keytab file with --file")
	}

	// At most one modifying operation may be selected.
	mod := 0
	for _, b := range []bool{args.ktAdd, args.ktRemove, args.ktReplace, args.ktUpdateKvno} {
		if b {
			mod++
		}
	}
	if mod > 1 {
		ktUsage("Choose at most ONE of --add, --remove, --replace, --update-kvno")
	}
	// Treat supplied key material without an explicit operation as an implicit
	// --add, so "--create --kt-pass ..." (or pointing --file at an existing
	// keytab with key material) does the obvious thing instead of writing an
	// empty/unchanged keytab.
	if mod == 0 && ktHasKeyMaterial(args) {
		args.ktAdd = true
		mod = 1
	}
	if args.ktKvno < 0 {
		ktUsage("--kvno cannot be negative")
	}

	// Build the in-memory keytab: start empty for --create (refusing to clobber),
	// otherwise load the existing file.
	var kt *keytab.Keytab
	if args.ktCreate {
		if _, statErr := os.Stat(args.ktFile); statErr == nil {
			return fmt.Errorf("Refusing to overwrite existing file %s with --create", args.ktFile)
		}
		kt = keytab.New()
	} else {
		kt, err = keytab.Load(args.ktFile)
		if err != nil {
			return fmt.Errorf("Failed to load keytab %s: %s", args.ktFile, err)
		}
	}

	// Creating an empty keytab is itself a write.
	modified := args.ktCreate

	switch {
	case args.ktAdd:
		if err = ktAddEntries(args, kt); err != nil {
			return
		}
		modified = true
	case args.ktRemove:
		comps, realm, etypeFilter := ktMatchCriteria(args, true)
		n := ktRemoveMatching(kt, comps, realm, etypeFilter, args.ktMatchKvno)
		fmt.Printf("Removed %d matching entr%s\n", n, plural(n))
		modified = true
	case args.ktReplace:
		// Replace ignores the enctype filter: --enctype selects which keys to
		// derive from a password, not which to drop. Remove every entry for the
		// principal (optionally narrowed by --match-kvno), then add the new ones.
		comps, realm, _ := ktMatchCriteria(args, false)
		n := ktRemoveMatching(kt, comps, realm, 0, args.ktMatchKvno)
		if err = ktAddEntries(args, kt); err != nil {
			return
		}
		fmt.Printf("Replaced entries for %s@%s (removed %d, added new key material)\n", args.ktPrincipal, realm, n)
		modified = true
	case args.ktUpdateKvno:
		comps, realm, etypeFilter := ktMatchCriteria(args, true)
		n := ktUpdateKvnoMatching(kt, comps, realm, etypeFilter, args.ktMatchKvno, args.ktKvno)
		fmt.Printf("Set kvno=%d on %d matching entr%s\n", args.ktKvno, n, plural(n))
		modified = true
	}

	if modified {
		if err = ktWrite(kt, args.ktFile); err != nil {
			return
		}
		fmt.Printf("Wrote keytab to %s\n", args.ktFile)
	}

	// Show the resulting contents after a change, or when just listing.
	if modified || args.ktList || mod == 0 {
		fmt.Print(ktRender(kt))
	}
	return nil
}

// ktMatchCriteria validates and returns the principal components, realm and
// (optional) enctype filter used to select entries for remove/replace/update-kvno.
// When useEnctypeFilter is true and --enctype is supplied, the first listed
// enctype is used as a filter.
func ktMatchCriteria(args *userArgs, useEnctypeFilter bool) (comps []string, realm string, etypeFilter int32) {
	if args.ktPrincipal == "" {
		ktUsage("Must specify --principal for this operation")
	}
	realm = ktResolveRealm(args)
	pn, _ := types.ParseSPNString(args.ktPrincipal)
	comps = pn.NameString
	if useEnctypeFilter && len(args.ktEnctypes) > 0 {
		etypeFilter = etypeID.EtypeSupported(strings.ToLower(args.ktEnctypes[0]))
		if etypeFilter == 0 {
			ktUsage("Unsupported or unknown enctype filter: %q", args.ktEnctypes[0])
		}
	}
	return
}

// ktResolveRealm returns the uppercased realm for the operation, falling back to
// the connection domain when --query-salt is used without an explicit --realm.
func ktResolveRealm(args *userArgs) string {
	realm := strings.ToUpper(args.ktRealm)
	if realm == "" {
		if args.querySalt && args.userDomainUpper != "" {
			return args.userDomainUpper
		}
		ktUsage("Must specify --realm for this operation")
	}
	return realm
}

// ktAddEntries adds keytab entries from the supplied key material (password,
// NT hash, AES128 and/or AES256). Password entries derive one key per resolved
// enctype, using the KDC-queried salt when --query-salt is set.
func ktAddEntries(args *userArgs, kt *keytab.Keytab) error {
	if args.ktPrincipal == "" {
		ktUsage("Must specify --principal when adding an entry")
	}
	realm := ktResolveRealm(args)
	cname := types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, args.ktPrincipal)
	ts := time.Now()
	added := false

	if args.ktPassword != "" && args.ktPasswordHex != nil {
		ktUsage("Choose only ONE of --kt-pass and --kt-pass-hex")
	}
	if args.ktPassword != "" || args.ktPasswordHex != nil {
		// --kt-pass-hex carries a raw (binary) password as hex, typically an AD
		// machine account password, which Windows stores as its UTF-16LE blob.
		// AES string-to-key operates on the UTF-8 form of the cleartext, so decode
		// the UTF-16LE bytes to UTF-8 for those etypes; RC4 (handled in the loop)
		// is MD4 of the UTF-16LE bytes directly.
		hexPass := args.ktPasswordHex != nil
		secret := args.ktPassword
		if hexPass {
			s, cerr := utf16leToUTF8(args.ktPasswordHex)
			if cerr != nil {
				return fmt.Errorf("--kt-pass-hex must be a UTF-16LE password blob: %s", cerr)
			}
			secret = s
		}
		etypes, err := resolveEnctypes(args.ktEnctypes)
		if err != nil {
			return err
		}
		// --salt and --query-salt are mutually exclusive (enforced in main()).
		var pas types.PADataSequence
		if args.ktSalt != "" {
			fmt.Printf("Using explicit salt: %q\n", args.ktSalt)
			pas = types.PADataSequence{{PADataType: patype.PA_PW_SALT, PADataValue: []byte(args.ktSalt)}}
		} else if args.querySalt {
			if args.c == nil {
				return fmt.Errorf("--query-salt requires a KDC connection (client not initialized)")
			}
			salt, err := args.c.RequestSalt(cname, realm)
			if err != nil {
				return fmt.Errorf("failed to query salt from KDC: %s", err)
			}
			fmt.Printf("Using KDC-provided salt: %q\n", salt)
			pas = types.PADataSequence{{PADataType: patype.PA_PW_SALT, PADataValue: []byte(salt)}}
		} else {
			fmt.Printf("Using default salt: %q (override with --salt or --query-salt)\n", cname.GetSalt(realm))
		}
		for _, et := range etypes {
			var keyBytes []byte
			if hexPass && et == etypeID.RC4_HMAC {
				// The NT hash (RC4 key) is MD4 of the UTF-16LE password bytes.
				// gokrb5's RC4 string-to-key ranges over the secret as UTF-8 runes
				// and re-encodes UTF-16LE, which would double-encode the already
				// UTF-16LE bytes, so compute the hash directly here.
				h := md4.New()
				h.Write(args.ktPasswordHex)
				keyBytes = h.Sum(nil)
			} else {
				key, _, err := crypto.GetKeyFromPassword(secret, cname, realm, et, pas)
				if err != nil {
					return fmt.Errorf("failed to derive key for etype %d: %s", et, err)
				}
				keyBytes = key.KeyValue
			}
			if err := ktAddKey(kt, args.ktPrincipal, realm, keyBytes, ts, args.ktKvno, et); err != nil {
				return err
			}
			added = true
		}
	}
	if args.ktHash != nil {
		if len(args.ktHash) != 16 {
			return fmt.Errorf("--kt-hash must be a 16-byte (32 hex character) NT hash")
		}
		if err := ktAddKey(kt, args.ktPrincipal, realm, args.ktHash, ts, args.ktKvno, etypeID.RC4_HMAC); err != nil {
			return err
		}
		added = true
	}
	if args.ktAes128 != nil {
		if len(args.ktAes128) != 16 {
			return fmt.Errorf("--kt-aes128 must be a 16-byte (32 hex character) AES128 key")
		}
		if err := ktAddKey(kt, args.ktPrincipal, realm, args.ktAes128, ts, args.ktKvno, etypeID.AES128_CTS_HMAC_SHA1_96); err != nil {
			return err
		}
		added = true
	}
	if args.ktAes256 != nil {
		if len(args.ktAes256) != 32 {
			return fmt.Errorf("--kt-aes256 must be a 32-byte (64 hex character) AES256 key")
		}
		if err := ktAddKey(kt, args.ktPrincipal, realm, args.ktAes256, ts, args.ktKvno, etypeID.AES256_CTS_HMAC_SHA1_96); err != nil {
			return err
		}
		added = true
	}
	if !added {
		ktUsage("No key material provided. Use one or more of --kt-pass, --kt-hash, --kt-aes128, --kt-aes256")
	}
	return nil
}

// ktAddKey appends a single raw-key entry and stamps the requested kvno on both
// the 8-bit and 32-bit kvno fields (AddKeyEntry only sets them from the uint8,
// so this also lets the 32-bit kvno carry values beyond 255).
func ktAddKey(kt *keytab.Keytab, principal, realm string, key []byte, ts time.Time, kvno int, et int32) error {
	if err := kt.AddKeyEntry(principal, realm, key, ts, uint8(kvno), et); err != nil {
		return err
	}
	last := len(kt.Entries) - 1
	if last >= 0 {
		kt.Entries[last].KVNO = uint32(kvno)
		kt.Entries[last].KVNO8 = uint8(kvno)
	}
	return nil
}

// ktRemoveMatching removes (by in-place compaction) every entry matching the
// principal/realm and optional enctype/kvno filters, returning the count removed.
func ktRemoveMatching(kt *keytab.Keytab, comps []string, realm string, etypeFilter int32, matchKvno int) int {
	n := 0
	for _, e := range kt.Entries {
		if principalMatches(e.Principal.Components, e.Principal.Realm, e.Key.KeyType, e.KVNO, comps, realm, etypeFilter, matchKvno) {
			continue
		}
		kt.Entries[n] = e
		n++
	}
	removed := len(kt.Entries) - n
	kt.Entries = kt.Entries[:n]
	return removed
}

// ktUpdateKvnoMatching sets the kvno of every matching entry, returning the count.
func ktUpdateKvnoMatching(kt *keytab.Keytab, comps []string, realm string, etypeFilter int32, matchKvno, newKvno int) int {
	n := 0
	for i := range kt.Entries {
		if principalMatches(kt.Entries[i].Principal.Components, kt.Entries[i].Principal.Realm, kt.Entries[i].Key.KeyType, kt.Entries[i].KVNO, comps, realm, etypeFilter, matchKvno) {
			kt.Entries[i].KVNO = uint32(newKvno)
			kt.Entries[i].KVNO8 = uint8(newKvno)
			n++
		}
	}
	return n
}

// principalMatches reports whether a keytab entry (described by its extracted
// fields) matches the requested principal components, realm and optional filters.
// Component and realm comparison is case-insensitive; an etypeFilter of 0 or a
// matchKvno below 0 means "any".
func principalMatches(eComps []string, eRealm string, eType int32, eKvno uint32, comps []string, realm string, etypeFilter int32, matchKvno int) bool {
	if !strings.EqualFold(eRealm, realm) {
		return false
	}
	if len(eComps) != len(comps) {
		return false
	}
	for i := range comps {
		if !strings.EqualFold(eComps[i], comps[i]) {
			return false
		}
	}
	if etypeFilter != 0 && eType != etypeFilter {
		return false
	}
	if matchKvno >= 0 && int(eKvno) != matchKvno {
		return false
	}
	return true
}

// resolveEnctypes maps the --enctype names (or the AD-like default set) to gokrb5
// enctype IDs.
func resolveEnctypes(list stringList) ([]int32, error) {
	names := []string(list)
	if len(names) == 0 {
		names = defaultKeytabEnctypes
	}
	out := make([]int32, 0, len(names))
	for _, n := range names {
		id := etypeID.EtypeSupported(strings.ToLower(n))
		if id == 0 {
			return nil, fmt.Errorf("unsupported or unknown enctype: %q", n)
		}
		out = append(out, id)
	}
	return out, nil
}

// utf16leToUTF8 converts a UTF-16LE byte blob (such as an AD machine account
// password) to the UTF-8 string used as the AES string-to-key secret. Valid
// surrogate pairs become their combined code point; unpaired surrogates become
// U+FFFD. This matches the de-facto reference (Impacket's
// decode('utf-16-le','replace').encode('utf-8')) and therefore the keys the DC
// computes.
func utf16leToUTF8(b []byte) (string, error) {
	if len(b)%2 != 0 {
		return "", fmt.Errorf("UTF-16LE length must be even, got %d bytes", len(b))
	}
	u16 := make([]uint16, len(b)/2)
	for i := range u16 {
		u16[i] = binary.LittleEndian.Uint16(b[i*2:])
	}
	return string(utf16.Decode(u16)), nil
}

// enctypeNames maps encryption type IDs to a canonical friendly name (matching
// the names accepted by --enctype).
var enctypeNames = map[int32]string{
	etypeID.DES3_CBC_SHA1_KD:           "des3-cbc-sha1",
	etypeID.AES128_CTS_HMAC_SHA1_96:    "aes128-cts-hmac-sha1-96",
	etypeID.AES256_CTS_HMAC_SHA1_96:    "aes256-cts-hmac-sha1-96",
	etypeID.AES128_CTS_HMAC_SHA256_128: "aes128-cts-hmac-sha256-128",
	etypeID.AES256_CTS_HMAC_SHA384_192: "aes256-cts-hmac-sha384-192",
	etypeID.RC4_HMAC:                   "rc4-hmac",
}

func enctypeName(id int32) string {
	if n, ok := enctypeNames[id]; ok {
		return n
	}
	return "unknown"
}

// ktRender renders the keytab as a table, like the library's String() but with a
// friendly enctype name column alongside the numeric etype.
func ktRender(kt *keytab.Keytab) string {
	var sb strings.Builder

	// Size the principal column to the longest principal so every name fits
	// without wasting width, but never narrower than the header.
	principals := make([]string, len(kt.Entries))
	principalWidth := len("Principal")
	for i, e := range kt.Entries {
		principals[i] = strings.Join(e.Principal.Components, "/") + "@" + e.Principal.Realm
		if l := len(principals[i]); l > principalWidth {
			principalWidth = l
		}
	}

	fmt.Fprintf(&sb, "%-4s %-17s %-*s %2s %-26s %s\n", "KVNO", "Timestamp", principalWidth, "Principal", "ET", "Enctype", "Key")
	fmt.Fprintf(&sb, "%-4s %-17s %-*s %2s %-26s %s\n",
		"----", strings.Repeat("-", 17), principalWidth, strings.Repeat("-", principalWidth), "--", strings.Repeat("-", 26), strings.Repeat("-", 64))
	for i, e := range kt.Entries {
		fmt.Fprintf(&sb, "% 4d %-17s %-*s %2d %-26s %x\n",
			e.KVNO,
			e.Timestamp.Format("02/01/06 15:04:05"),
			principalWidth,
			principals[i],
			e.Key.KeyType,
			enctypeName(e.Key.KeyType),
			e.Key.KeyValue,
		)
	}
	return sb.String()
}

// ktHasKeyMaterial reports whether any add/replace key source was supplied.
func ktHasKeyMaterial(args *userArgs) bool {
	return args.ktPassword != "" || args.ktPasswordHex != nil || args.ktHash != nil || args.ktAes128 != nil || args.ktAes256 != nil
}

func ktWrite(kt *keytab.Keytab, path string) error {
	b, err := kt.Marshal()
	if err != nil {
		return fmt.Errorf("failed to marshal keytab: %s", err)
	}
	if err := os.WriteFile(path, b, 0600); err != nil {
		return fmt.Errorf("failed to write keytab to %s: %s", path, err)
	}
	return nil
}

func plural(n int) string {
	if n == 1 {
		return "y"
	}
	return "ies"
}
