//go:build !noasm || !appengine
// +build !noasm !appengine

// Code generated by asm2asm, DO NOT EDIT.

package avx2

import (
	"github.com/bytedance/sonic/loader"
)

const (
	_entry__skip_one_fast = 336
)

const (
	_stack__skip_one_fast = 176
)

const (
	_size__skip_one_fast = 2824
)

var (
	_pcsp__skip_one_fast = [][2]uint32{
		{0x1, 0},
		{0x6, 8},
		{0x8, 16},
		{0xa, 24},
		{0xc, 32},
		{0xd, 40},
		{0x14, 48},
		{0x32c, 176},
		{0x32d, 48},
		{0x32f, 40},
		{0x331, 32},
		{0x333, 24},
		{0x335, 16},
		{0x336, 8},
		{0x33a, 0},
		{0xb08, 176},
	}
)

var _cfunc_skip_one_fast = []loader.CFunc{
	{"_skip_one_fast_entry", 0, _entry__skip_one_fast, 0, nil},
	{"_skip_one_fast", _entry__skip_one_fast, _size__skip_one_fast, _stack__skip_one_fast, _pcsp__skip_one_fast},
}
