// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Package keywrap provides an AES-KW keywrap implementation as defined in RFC-3394
//
// https://github.com/NickBall/go-aes-key-wrap/
//
// MIT License
//
// Copyright (c) 2017 Nick Ball
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

// This package has modified AESUnwrap function from  https://github.com/NickBall/go-aes-key-wrap/
// to unwrap per 5649 protocol

package common

import (
	"crypto/cipher"
	"crypto/subtle"
	"encoding/binary"

	"github.com/pkg/errors"
)

// AIV (alternate IV) as specified in RFC-5649
var AIV = []byte{0xA6, 0x59, 0x59, 0xA6}

// AESUnwrapPadding decrypts the provided cipher text with the given AES cipher
// (and corresponding key), using the AES Key Wrap algorithm (RFC-5649). The
// decrypted cipher text is verified using the alternative IV and will return an
// error if validation fails.
func AesUnwrapPadding(block cipher.Block, cipherText []byte) ([]byte, error) {
	a := make([]byte, 8)
	c := make([]byte, len(cipherText)-8)
	n := (len(cipherText) / 8) - 1

	if n == 1 {
		/* RFC-5649: If n is one (n=1), the ciphertext contains exactly two 64-bit
		 * blocks (C[0] and C[1]), and they are decrypted as a single AES
		 * block using AES in ECB mode [Modes] with K (the KEK) to recover
		 * the AIV and the padded plaintext key: A | P[1] = DEC(K, C[0] | C[1]).
		 */

		r := make([]byte, 16)
		block.Decrypt(r, cipherText)

		copy(a, r[:8])
		copy(c, r[8:16])
	} else {
		/* RFC-5649: Executes Steps 1 and 2 of the unwrapping process specified
		 * in Section 2.2.2 of RFC-3394
		 */
		r := make([][]byte, n)
		for i := range r {
			r[i] = make([]byte, 8)
			copy(r[i], cipherText[(i+1)*8:])
		}
		copy(a, cipherText[:8])

		// Compute intermediate values
		for j := 5; j >= 0; j-- {
			for i := n; i >= 1; i-- {
				t := (n * j) + i
				tBytes := make([]byte, 8)
				binary.BigEndian.PutUint64(tBytes, uint64(t))

				b := arrConcat(arrXor(a, tBytes), r[i-1])
				block.Decrypt(b, b)

				copy(a, b[:len(b)/2])
				copy(r[i-1], b[len(b)/2:])
			}
		}

		// Output
		c = arrConcat(r...)
	}

	/*
	 * RFC-5649 uses an AIV and MLI which are set as follows:
	 * high 4 bytes are set to 0xA65959A6 (AIV)
	 * low 4 bytes are set to the length of the key data in octets (MLI)
	 */

	aHi := make([]byte, 4)
	copy(aHi, a[:4])

	if subtle.ConstantTimeCompare(aHi, AIV) != 1 {
		return nil, errors.Errorf("integrity check failed - unexpected AIV %v", aHi)
	}

	aLo := make([]byte, 4)
	copy(aLo, a[4:8])
	MLI := binary.BigEndian.Uint32(aLo)

	if MLI <= 8*(uint32(n)-1) || MLI > 8*uint32(n) {
		return nil, errors.Errorf("integrity check failed - unexpected MLI %v", aLo)
	}

	b := 8*uint32(n) - MLI

	for i := uint32(0); i < b; i++ {
		if c[i+MLI] != 0 {
			return nil, errors.New("integrity check failed - padded key data is not zero")
		}
	}

	cUnpadded := make([]byte, MLI)
	copy(cUnpadded, c[:MLI])

	return cUnpadded, nil
}

func arrConcat(arrays ...[]byte) []byte {
	out := make([]byte, len(arrays[0]))
	copy(out, arrays[0])
	for _, array := range arrays[1:] {
		out = append(out, array...)
	}

	return out
}

func arrXor(arrL []byte, arrR []byte) []byte {
	out := make([]byte, len(arrL))
	for x := range arrL {
		out[x] = arrL[x] ^ arrR[x]
	}
	return out
}
