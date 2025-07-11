//go:build !noasm || !appengine
// +build !noasm !appengine

// Code generated by asm2asm, DO NOT EDIT.

package avx2

import (
	"github.com/bytedance/sonic/loader"
)

const (
	_entry__lookup_small_key = 96
)

const (
	_stack__lookup_small_key = 56
)

const (
	_size__lookup_small_key = 810
)

var (
	_pcsp__lookup_small_key = [][2]uint32{
		{0x1, 0},
		{0x6, 8},
		{0x8, 16},
		{0xa, 24},
		{0xc, 32},
		{0xd, 40},
		{0xe, 48},
		{0x2fc, 56},
		{0x2fd, 48},
		{0x2ff, 40},
		{0x301, 32},
		{0x303, 24},
		{0x305, 16},
		{0x306, 8},
		{0x30a, 0},
		{0x32a, 56},
	}
)

var _cfunc_lookup_small_key = []loader.CFunc{
	{"_lookup_small_key_entry", 0, _entry__lookup_small_key, 0, nil},
	{"_lookup_small_key", _entry__lookup_small_key, _size__lookup_small_key, _stack__lookup_small_key, _pcsp__lookup_small_key},
}
