package aesrw

import "fmt"
import "math/rand"
import "testing"

//Characters to use in random strings
const CHRB = "!\"#$%&\\'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~\x7f"
//Max string length to test
const MAXL = 999

//Generate a slice of random bytes of length n
//using characters in CHRB
func RandomBytes(n int) []byte {
    s := make([]byte, n)
    l64 := int64(len(CHRB))
    for i := range s {
        s[i] = CHRB[rand.Int63() % l64]
    }
    return s
}

//Generate a slice of random string of length n
//using characters in CHRB
func RandomString(n int) string {
    return string(RandomBytes(n))
}


//Test generating random strings, encrypting them, decrypting them
//and verifying the result is same as the start
func TestString(t *testing.T) {
    var keyLen = []int { 16, 24, 32 }
    for i := 0; i < 999; i++ {
        k  := RandomBytes(keyLen[i % len(keyLen)])  //Random encryption key of length 16, 24 or 32
        s1    := RandomString(rand.Int() % MAXL)    //Random start
        s2, e := EncryptString(s1, k)               //Encrypted
        if e != nil {
            t.Error(fmt.Sprintf("%s", e))
        }
        s3, e := DecryptString(s2, k)               //Decrypted
        if e != nil {
            t.Error(fmt.Sprintf("%s", e))
        }
        if s1 != s3 {
            t.Error("Original and decrypted strings do not match!")
        }
    }
}