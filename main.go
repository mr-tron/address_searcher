package main

import (
	"crypto/rand"
	"strings"
	"fmt"
	"regexp"
	"os"
	"crypto/sha256"
	"github.com/piotrnar/gocoin/lib/secp256k1"
	"golang.org/x/crypto/ripemd160"
)

func main()  {
	if len(os.Args) != 3 {
		panic("required 2 args: currency name and regex. \n example: ./searcher dash 'petya|vasya'")
	}
	r, err := regexp.Compile(os.Args[2])
	if err!= nil {
		panic("Bad regular expression")
	}

	regex_match(r, os.Args[1])

}
type Currency struct {
	pub_prefix byte
	priv_prefix byte
}
var CURRENCIES  = map[string]Currency{
	"btc": {pub_prefix:0, priv_prefix:128},
	"dash": {pub_prefix: 76, priv_prefix:204},
}


const b58digits_ordered string = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

func Encode58(bin []byte) []byte {
	binsz := len(bin)
	var i, j, high, zcount int
	var carry uint16
	for zcount < binsz && bin[zcount] == 0 {
		zcount++
	}

	size := (binsz-zcount)*138/100 + 1
	var buf = make([]byte, size)

	high = size - 1
	for i = zcount; i < binsz; i += 1 {
		j = size - 1
		for carry = uint16(bin[i]); j > high || carry != 0; j -= 1 {
			carry = carry + 256*uint16(buf[j])
			buf[j] = byte(carry % 58)
			carry /= 58
		}
		high = j
	}

	for j = 0; j < size && buf[j] == 0; j += 1 {
	}

	var b58 = make([]byte, size-j+zcount)

	if zcount != 0 {
		for i = 0; i < zcount; i++ {
			b58[i] = '1'
		}
	}

	for i = zcount; j < size; i += 1 {
		b58[i] = b58digits_ordered[buf[j]]
		j += 1
	}

	return b58
}

var buf_encode_priv_to58 = make([]byte, 38)
func EncodePrivKeyTo58(priv []byte, compressed bool, network_prefix byte) []byte {


	buf_encode_priv_to58[0] = network_prefix
	copy(buf_encode_priv_to58[1:33], priv)

	if compressed{
		buf_encode_priv_to58[33] = 0x01
		DoubleShaHash(buf_encode_priv_to58[:34], buf_encode_priv_to58[34:38])
		return Encode58(buf_encode_priv_to58)
	} else {
		DoubleShaHash(buf_encode_priv_to58[:33], buf_encode_priv_to58[33:37])
		return Encode58(buf_encode_priv_to58[:37])
	}

}

var buf_sha_double_hasher =  make([]byte, 32)
func DoubleShaHash(b []byte, out []byte) {
	s := sha256.New()
	s.Write(b)
	buf_sha_double_hasher = s.Sum(nil)
	s.Reset()
	s.Write(buf_sha_double_hasher)
	copy(out, s.Sum(nil))
}
func RimpHash(in []byte) []byte {
	sha := sha256.New()
	sha.Write(in)
	rim := ripemd160.New()
	rim.Write(sha.Sum(nil)[:])
	return rim.Sum(nil)
}

func PublicFromPrivate(priv_key []byte, res []byte) {
	if !secp256k1.BaseMultiply(priv_key, res) {
		panic("Cant encode priv to public")
	}

}

func regex_match(r *regexp.Regexp, currency_name string) {
	var encoded string
	priv_bytes := make([]byte, 32)
	pub_bytes := make([]byte, 65)
	pub_hashed := make([]byte, 25)

	currency, prs := CURRENCIES[currency_name]
	if !prs {
		panic("unknown currency")
	}
	pub_prefix := currency.pub_prefix
	priv_prefix := currency.priv_prefix
	for {
		rand.Read(priv_bytes)
		PublicFromPrivate(priv_bytes, pub_bytes)

		copy(pub_hashed[1:22], RimpHash(pub_bytes))
		pub_hashed[0] = pub_prefix
		DoubleShaHash(pub_hashed[:21], pub_hashed[21:])

		encoded = string(Encode58(pub_hashed))

		if r.MatchString(strings.ToLower(encoded)) {
			fmt.Println(encoded, string(EncodePrivKeyTo58(priv_bytes, false, priv_prefix)))
		}
	}
}
