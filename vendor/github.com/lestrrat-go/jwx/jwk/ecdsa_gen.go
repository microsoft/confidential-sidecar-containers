// This file is auto-generated. DO NOT EDIT

package jwk

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"fmt"
	"sort"
	"sync"

	"github.com/lestrrat-go/iter/mapiter"
	"github.com/lestrrat-go/jwx/internal/base64"
	"github.com/lestrrat-go/jwx/internal/iter"
	"github.com/lestrrat-go/jwx/internal/json"
	"github.com/lestrrat-go/jwx/internal/pool"
	"github.com/lestrrat-go/jwx/jwa"
	"github.com/pkg/errors"
)

const (
	ECDSACrvKey = "crv"
	ECDSADKey   = "d"
	ECDSAXKey   = "x"
	ECDSAYKey   = "y"
)

type ECDSAPrivateKey interface {
	Key
	FromRaw(*ecdsa.PrivateKey) error
	Crv() jwa.EllipticCurveAlgorithm
	D() []byte
	X() []byte
	Y() []byte
}

type ecdsaPrivateKey struct {
	algorithm              *string // https://tools.ietf.org/html/rfc7517#section-4.4
	crv                    *jwa.EllipticCurveAlgorithm
	d                      []byte
	keyID                  *string           // https://tools.ietf.org/html/rfc7515#section-4.1.4
	keyUsage               *string           // https://tools.ietf.org/html/rfc7517#section-4.2
	keyops                 *KeyOperationList // https://tools.ietf.org/html/rfc7517#section-4.3
	x                      []byte
	x509CertChain          *CertificateChain // https://tools.ietf.org/html/rfc7515#section-4.1.6
	x509CertThumbprint     *string           // https://tools.ietf.org/html/rfc7515#section-4.1.7
	x509CertThumbprintS256 *string           // https://tools.ietf.org/html/rfc7515#section-4.1.8
	x509URL                *string           // https://tools.ietf.org/html/rfc7515#section-4.1.5
	y                      []byte
	privateParams          map[string]interface{}
	mu                     *sync.RWMutex
	dc                     DecodeCtx
}

func NewECDSAPrivateKey() ECDSAPrivateKey {
	return newECDSAPrivateKey()
}

func newECDSAPrivateKey() *ecdsaPrivateKey {
	return &ecdsaPrivateKey{
		mu:            &sync.RWMutex{},
		privateParams: make(map[string]interface{}),
	}
}

func (h ecdsaPrivateKey) KeyType() jwa.KeyType {
	return jwa.EC
}

func (h *ecdsaPrivateKey) Algorithm() string {
	if h.algorithm != nil {
		return *(h.algorithm)
	}
	return ""
}

func (h *ecdsaPrivateKey) Crv() jwa.EllipticCurveAlgorithm {
	if h.crv != nil {
		return *(h.crv)
	}
	return jwa.InvalidEllipticCurve
}

func (h *ecdsaPrivateKey) D() []byte {
	return h.d
}

func (h *ecdsaPrivateKey) KeyID() string {
	if h.keyID != nil {
		return *(h.keyID)
	}
	return ""
}

func (h *ecdsaPrivateKey) KeyUsage() string {
	if h.keyUsage != nil {
		return *(h.keyUsage)
	}
	return ""
}

func (h *ecdsaPrivateKey) KeyOps() KeyOperationList {
	if h.keyops != nil {
		return *(h.keyops)
	}
	return nil
}

func (h *ecdsaPrivateKey) X() []byte {
	return h.x
}

func (h *ecdsaPrivateKey) X509CertChain() []*x509.Certificate {
	if h.x509CertChain != nil {
		return h.x509CertChain.Get()
	}
	return nil
}

func (h *ecdsaPrivateKey) X509CertThumbprint() string {
	if h.x509CertThumbprint != nil {
		return *(h.x509CertThumbprint)
	}
	return ""
}

func (h *ecdsaPrivateKey) X509CertThumbprintS256() string {
	if h.x509CertThumbprintS256 != nil {
		return *(h.x509CertThumbprintS256)
	}
	return ""
}

func (h *ecdsaPrivateKey) X509URL() string {
	if h.x509URL != nil {
		return *(h.x509URL)
	}
	return ""
}

func (h *ecdsaPrivateKey) Y() []byte {
	return h.y
}

func (h *ecdsaPrivateKey) makePairs() []*HeaderPair {
	h.mu.RLock()
	defer h.mu.RUnlock()

	var pairs []*HeaderPair
	pairs = append(pairs, &HeaderPair{Key: "kty", Value: jwa.EC})
	if h.algorithm != nil {
		pairs = append(pairs, &HeaderPair{Key: AlgorithmKey, Value: *(h.algorithm)})
	}
	if h.crv != nil {
		pairs = append(pairs, &HeaderPair{Key: ECDSACrvKey, Value: *(h.crv)})
	}
	if h.d != nil {
		pairs = append(pairs, &HeaderPair{Key: ECDSADKey, Value: h.d})
	}
	if h.keyID != nil {
		pairs = append(pairs, &HeaderPair{Key: KeyIDKey, Value: *(h.keyID)})
	}
	if h.keyUsage != nil {
		pairs = append(pairs, &HeaderPair{Key: KeyUsageKey, Value: *(h.keyUsage)})
	}
	if h.keyops != nil {
		pairs = append(pairs, &HeaderPair{Key: KeyOpsKey, Value: *(h.keyops)})
	}
	if h.x != nil {
		pairs = append(pairs, &HeaderPair{Key: ECDSAXKey, Value: h.x})
	}
	if h.x509CertChain != nil {
		pairs = append(pairs, &HeaderPair{Key: X509CertChainKey, Value: *(h.x509CertChain)})
	}
	if h.x509CertThumbprint != nil {
		pairs = append(pairs, &HeaderPair{Key: X509CertThumbprintKey, Value: *(h.x509CertThumbprint)})
	}
	if h.x509CertThumbprintS256 != nil {
		pairs = append(pairs, &HeaderPair{Key: X509CertThumbprintS256Key, Value: *(h.x509CertThumbprintS256)})
	}
	if h.x509URL != nil {
		pairs = append(pairs, &HeaderPair{Key: X509URLKey, Value: *(h.x509URL)})
	}
	if h.y != nil {
		pairs = append(pairs, &HeaderPair{Key: ECDSAYKey, Value: h.y})
	}
	for k, v := range h.privateParams {
		pairs = append(pairs, &HeaderPair{Key: k, Value: v})
	}
	return pairs
}

func (h *ecdsaPrivateKey) PrivateParams() map[string]interface{} {
	return h.privateParams
}

func (h *ecdsaPrivateKey) Get(name string) (interface{}, bool) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	switch name {
	case KeyTypeKey:
		return h.KeyType(), true
	case AlgorithmKey:
		if h.algorithm == nil {
			return nil, false
		}
		return *(h.algorithm), true
	case ECDSACrvKey:
		if h.crv == nil {
			return nil, false
		}
		return *(h.crv), true
	case ECDSADKey:
		if h.d == nil {
			return nil, false
		}
		return h.d, true
	case KeyIDKey:
		if h.keyID == nil {
			return nil, false
		}
		return *(h.keyID), true
	case KeyUsageKey:
		if h.keyUsage == nil {
			return nil, false
		}
		return *(h.keyUsage), true
	case KeyOpsKey:
		if h.keyops == nil {
			return nil, false
		}
		return *(h.keyops), true
	case ECDSAXKey:
		if h.x == nil {
			return nil, false
		}
		return h.x, true
	case X509CertChainKey:
		if h.x509CertChain == nil {
			return nil, false
		}
		return h.x509CertChain.Get(), true
	case X509CertThumbprintKey:
		if h.x509CertThumbprint == nil {
			return nil, false
		}
		return *(h.x509CertThumbprint), true
	case X509CertThumbprintS256Key:
		if h.x509CertThumbprintS256 == nil {
			return nil, false
		}
		return *(h.x509CertThumbprintS256), true
	case X509URLKey:
		if h.x509URL == nil {
			return nil, false
		}
		return *(h.x509URL), true
	case ECDSAYKey:
		if h.y == nil {
			return nil, false
		}
		return h.y, true
	default:
		v, ok := h.privateParams[name]
		return v, ok
	}
}

func (h *ecdsaPrivateKey) Set(name string, value interface{}) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.setNoLock(name, value)
}

func (h *ecdsaPrivateKey) setNoLock(name string, value interface{}) error {
	switch name {
	case "kty":
		return nil
	case AlgorithmKey:
		switch v := value.(type) {
		case string:
			h.algorithm = &v
		case fmt.Stringer:
			tmp := v.String()
			h.algorithm = &tmp
		default:
			return errors.Errorf(`invalid type for %s key: %T`, AlgorithmKey, value)
		}
		return nil
	case ECDSACrvKey:
		if v, ok := value.(jwa.EllipticCurveAlgorithm); ok {
			h.crv = &v
			return nil
		}
		return errors.Errorf(`invalid value for %s key: %T`, ECDSACrvKey, value)
	case ECDSADKey:
		if v, ok := value.([]byte); ok {
			h.d = v
			return nil
		}
		return errors.Errorf(`invalid value for %s key: %T`, ECDSADKey, value)
	case KeyIDKey:
		if v, ok := value.(string); ok {
			h.keyID = &v
			return nil
		}
		return errors.Errorf(`invalid value for %s key: %T`, KeyIDKey, value)
	case KeyUsageKey:
		switch v := value.(type) {
		case KeyUsageType:
			switch v {
			case ForSignature, ForEncryption:
				tmp := v.String()
				h.keyUsage = &tmp
			default:
				return errors.Errorf(`invalid key usage type %s`, v)
			}
		case string:
			h.keyUsage = &v
		default:
			return errors.Errorf(`invalid key usage type %s`, v)
		}
	case KeyOpsKey:
		var acceptor KeyOperationList
		if err := acceptor.Accept(value); err != nil {
			return errors.Wrapf(err, `invalid value for %s key`, KeyOpsKey)
		}
		h.keyops = &acceptor
		return nil
	case ECDSAXKey:
		if v, ok := value.([]byte); ok {
			h.x = v
			return nil
		}
		return errors.Errorf(`invalid value for %s key: %T`, ECDSAXKey, value)
	case X509CertChainKey:
		var acceptor CertificateChain
		if err := acceptor.Accept(value); err != nil {
			return errors.Wrapf(err, `invalid value for %s key`, X509CertChainKey)
		}
		h.x509CertChain = &acceptor
		return nil
	case X509CertThumbprintKey:
		if v, ok := value.(string); ok {
			h.x509CertThumbprint = &v
			return nil
		}
		return errors.Errorf(`invalid value for %s key: %T`, X509CertThumbprintKey, value)
	case X509CertThumbprintS256Key:
		if v, ok := value.(string); ok {
			h.x509CertThumbprintS256 = &v
			return nil
		}
		return errors.Errorf(`invalid value for %s key: %T`, X509CertThumbprintS256Key, value)
	case X509URLKey:
		if v, ok := value.(string); ok {
			h.x509URL = &v
			return nil
		}
		return errors.Errorf(`invalid value for %s key: %T`, X509URLKey, value)
	case ECDSAYKey:
		if v, ok := value.([]byte); ok {
			h.y = v
			return nil
		}
		return errors.Errorf(`invalid value for %s key: %T`, ECDSAYKey, value)
	default:
		if h.privateParams == nil {
			h.privateParams = map[string]interface{}{}
		}
		h.privateParams[name] = value
	}
	return nil
}

func (k *ecdsaPrivateKey) Remove(key string) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	switch key {
	case AlgorithmKey:
		k.algorithm = nil
	case ECDSACrvKey:
		k.crv = nil
	case ECDSADKey:
		k.d = nil
	case KeyIDKey:
		k.keyID = nil
	case KeyUsageKey:
		k.keyUsage = nil
	case KeyOpsKey:
		k.keyops = nil
	case ECDSAXKey:
		k.x = nil
	case X509CertChainKey:
		k.x509CertChain = nil
	case X509CertThumbprintKey:
		k.x509CertThumbprint = nil
	case X509CertThumbprintS256Key:
		k.x509CertThumbprintS256 = nil
	case X509URLKey:
		k.x509URL = nil
	case ECDSAYKey:
		k.y = nil
	default:
		delete(k.privateParams, key)
	}
	return nil
}

func (k *ecdsaPrivateKey) Clone() (Key, error) {
	return cloneKey(k)
}

func (k *ecdsaPrivateKey) DecodeCtx() DecodeCtx {
	k.mu.RLock()
	defer k.mu.RUnlock()
	return k.dc
}

func (k *ecdsaPrivateKey) SetDecodeCtx(dc DecodeCtx) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.dc = dc
}

func (h *ecdsaPrivateKey) UnmarshalJSON(buf []byte) error {
	h.algorithm = nil
	h.crv = nil
	h.d = nil
	h.keyID = nil
	h.keyUsage = nil
	h.keyops = nil
	h.x = nil
	h.x509CertChain = nil
	h.x509CertThumbprint = nil
	h.x509CertThumbprintS256 = nil
	h.x509URL = nil
	h.y = nil
	dec := json.NewDecoder(bytes.NewReader(buf))
LOOP:
	for {
		tok, err := dec.Token()
		if err != nil {
			return errors.Wrap(err, `error reading token`)
		}
		switch tok := tok.(type) {
		case json.Delim:
			// Assuming we're doing everything correctly, we should ONLY
			// get either '{' or '}' here.
			if tok == '}' { // End of object
				break LOOP
			} else if tok != '{' {
				return errors.Errorf(`expected '{', but got '%c'`, tok)
			}
		case string: // Objects can only have string keys
			switch tok {
			case KeyTypeKey:
				val, err := json.ReadNextStringToken(dec)
				if err != nil {
					return errors.Wrap(err, `error reading token`)
				}
				if val != jwa.EC.String() {
					return errors.Errorf(`invalid kty value for RSAPublicKey (%s)`, val)
				}
			case AlgorithmKey:
				if err := json.AssignNextStringToken(&h.algorithm, dec); err != nil {
					return errors.Wrapf(err, `failed to decode value for key %s`, AlgorithmKey)
				}
			case ECDSACrvKey:
				var decoded jwa.EllipticCurveAlgorithm
				if err := dec.Decode(&decoded); err != nil {
					return errors.Wrapf(err, `failed to decode value for key %s`, ECDSACrvKey)
				}
				h.crv = &decoded
			case ECDSADKey:
				if err := json.AssignNextBytesToken(&h.d, dec); err != nil {
					return errors.Wrapf(err, `failed to decode value for key %s`, ECDSADKey)
				}
			case KeyIDKey:
				if err := json.AssignNextStringToken(&h.keyID, dec); err != nil {
					return errors.Wrapf(err, `failed to decode value for key %s`, KeyIDKey)
				}
			case KeyUsageKey:
				if err := json.AssignNextStringToken(&h.keyUsage, dec); err != nil {
					return errors.Wrapf(err, `failed to decode value for key %s`, KeyUsageKey)
				}
			case KeyOpsKey:
				var decoded KeyOperationList
				if err := dec.Decode(&decoded); err != nil {
					return errors.Wrapf(err, `failed to decode value for key %s`, KeyOpsKey)
				}
				h.keyops = &decoded
			case ECDSAXKey:
				if err := json.AssignNextBytesToken(&h.x, dec); err != nil {
					return errors.Wrapf(err, `failed to decode value for key %s`, ECDSAXKey)
				}
			case X509CertChainKey:
				var decoded CertificateChain
				if err := dec.Decode(&decoded); err != nil {
					return errors.Wrapf(err, `failed to decode value for key %s`, X509CertChainKey)
				}
				h.x509CertChain = &decoded
			case X509CertThumbprintKey:
				if err := json.AssignNextStringToken(&h.x509CertThumbprint, dec); err != nil {
					return errors.Wrapf(err, `failed to decode value for key %s`, X509CertThumbprintKey)
				}
			case X509CertThumbprintS256Key:
				if err := json.AssignNextStringToken(&h.x509CertThumbprintS256, dec); err != nil {
					return errors.Wrapf(err, `failed to decode value for key %s`, X509CertThumbprintS256Key)
				}
			case X509URLKey:
				if err := json.AssignNextStringToken(&h.x509URL, dec); err != nil {
					return errors.Wrapf(err, `failed to decode value for key %s`, X509URLKey)
				}
			case ECDSAYKey:
				if err := json.AssignNextBytesToken(&h.y, dec); err != nil {
					return errors.Wrapf(err, `failed to decode value for key %s`, ECDSAYKey)
				}
			default:
				if dc := h.dc; dc != nil {
					if localReg := dc.Registry(); localReg != nil {
						decoded, err := localReg.Decode(dec, tok)
						if err == nil {
							h.setNoLock(tok, decoded)
							continue
						}
					}
				}
				decoded, err := registry.Decode(dec, tok)
				if err == nil {
					h.setNoLock(tok, decoded)
					continue
				}
				return errors.Wrapf(err, `could not decode field %s`, tok)
			}
		default:
			return errors.Errorf(`invalid token %T`, tok)
		}
	}
	if h.crv == nil {
		return errors.Errorf(`required field crv is missing`)
	}
	if h.d == nil {
		return errors.Errorf(`required field d is missing`)
	}
	if h.x == nil {
		return errors.Errorf(`required field x is missing`)
	}
	if h.y == nil {
		return errors.Errorf(`required field y is missing`)
	}
	return nil
}

func (h ecdsaPrivateKey) MarshalJSON() ([]byte, error) {
	data := make(map[string]interface{})
	fields := make([]string, 0, 12)
	for _, pair := range h.makePairs() {
		fields = append(fields, pair.Key.(string))
		data[pair.Key.(string)] = pair.Value
	}

	sort.Strings(fields)
	buf := pool.GetBytesBuffer()
	defer pool.ReleaseBytesBuffer(buf)
	buf.WriteByte('{')
	enc := json.NewEncoder(buf)
	for i, f := range fields {
		if i > 0 {
			buf.WriteRune(',')
		}
		buf.WriteRune('"')
		buf.WriteString(f)
		buf.WriteString(`":`)
		v := data[f]
		switch v := v.(type) {
		case []byte:
			buf.WriteRune('"')
			buf.WriteString(base64.EncodeToString(v))
			buf.WriteRune('"')
		default:
			if err := enc.Encode(v); err != nil {
				return nil, errors.Wrapf(err, `failed to encode value for field %s`, f)
			}
			buf.Truncate(buf.Len() - 1)
		}
	}
	buf.WriteByte('}')
	ret := make([]byte, buf.Len())
	copy(ret, buf.Bytes())
	return ret, nil
}

func (h *ecdsaPrivateKey) Iterate(ctx context.Context) HeaderIterator {
	pairs := h.makePairs()
	ch := make(chan *HeaderPair, len(pairs))
	go func(ctx context.Context, ch chan *HeaderPair, pairs []*HeaderPair) {
		defer close(ch)
		for _, pair := range pairs {
			select {
			case <-ctx.Done():
				return
			case ch <- pair:
			}
		}
	}(ctx, ch, pairs)
	return mapiter.New(ch)
}

func (h *ecdsaPrivateKey) Walk(ctx context.Context, visitor HeaderVisitor) error {
	return iter.WalkMap(ctx, h, visitor)
}

func (h *ecdsaPrivateKey) AsMap(ctx context.Context) (map[string]interface{}, error) {
	return iter.AsMap(ctx, h)
}

type ECDSAPublicKey interface {
	Key
	FromRaw(*ecdsa.PublicKey) error
	Crv() jwa.EllipticCurveAlgorithm
	X() []byte
	Y() []byte
}

type ecdsaPublicKey struct {
	algorithm              *string // https://tools.ietf.org/html/rfc7517#section-4.4
	crv                    *jwa.EllipticCurveAlgorithm
	keyID                  *string           // https://tools.ietf.org/html/rfc7515#section-4.1.4
	keyUsage               *string           // https://tools.ietf.org/html/rfc7517#section-4.2
	keyops                 *KeyOperationList // https://tools.ietf.org/html/rfc7517#section-4.3
	x                      []byte
	x509CertChain          *CertificateChain // https://tools.ietf.org/html/rfc7515#section-4.1.6
	x509CertThumbprint     *string           // https://tools.ietf.org/html/rfc7515#section-4.1.7
	x509CertThumbprintS256 *string           // https://tools.ietf.org/html/rfc7515#section-4.1.8
	x509URL                *string           // https://tools.ietf.org/html/rfc7515#section-4.1.5
	y                      []byte
	privateParams          map[string]interface{}
	mu                     *sync.RWMutex
	dc                     DecodeCtx
}

func NewECDSAPublicKey() ECDSAPublicKey {
	return newECDSAPublicKey()
}

func newECDSAPublicKey() *ecdsaPublicKey {
	return &ecdsaPublicKey{
		mu:            &sync.RWMutex{},
		privateParams: make(map[string]interface{}),
	}
}

func (h ecdsaPublicKey) KeyType() jwa.KeyType {
	return jwa.EC
}

func (h *ecdsaPublicKey) Algorithm() string {
	if h.algorithm != nil {
		return *(h.algorithm)
	}
	return ""
}

func (h *ecdsaPublicKey) Crv() jwa.EllipticCurveAlgorithm {
	if h.crv != nil {
		return *(h.crv)
	}
	return jwa.InvalidEllipticCurve
}

func (h *ecdsaPublicKey) KeyID() string {
	if h.keyID != nil {
		return *(h.keyID)
	}
	return ""
}

func (h *ecdsaPublicKey) KeyUsage() string {
	if h.keyUsage != nil {
		return *(h.keyUsage)
	}
	return ""
}

func (h *ecdsaPublicKey) KeyOps() KeyOperationList {
	if h.keyops != nil {
		return *(h.keyops)
	}
	return nil
}

func (h *ecdsaPublicKey) X() []byte {
	return h.x
}

func (h *ecdsaPublicKey) X509CertChain() []*x509.Certificate {
	if h.x509CertChain != nil {
		return h.x509CertChain.Get()
	}
	return nil
}

func (h *ecdsaPublicKey) X509CertThumbprint() string {
	if h.x509CertThumbprint != nil {
		return *(h.x509CertThumbprint)
	}
	return ""
}

func (h *ecdsaPublicKey) X509CertThumbprintS256() string {
	if h.x509CertThumbprintS256 != nil {
		return *(h.x509CertThumbprintS256)
	}
	return ""
}

func (h *ecdsaPublicKey) X509URL() string {
	if h.x509URL != nil {
		return *(h.x509URL)
	}
	return ""
}

func (h *ecdsaPublicKey) Y() []byte {
	return h.y
}

func (h *ecdsaPublicKey) makePairs() []*HeaderPair {
	h.mu.RLock()
	defer h.mu.RUnlock()

	var pairs []*HeaderPair
	pairs = append(pairs, &HeaderPair{Key: "kty", Value: jwa.EC})
	if h.algorithm != nil {
		pairs = append(pairs, &HeaderPair{Key: AlgorithmKey, Value: *(h.algorithm)})
	}
	if h.crv != nil {
		pairs = append(pairs, &HeaderPair{Key: ECDSACrvKey, Value: *(h.crv)})
	}
	if h.keyID != nil {
		pairs = append(pairs, &HeaderPair{Key: KeyIDKey, Value: *(h.keyID)})
	}
	if h.keyUsage != nil {
		pairs = append(pairs, &HeaderPair{Key: KeyUsageKey, Value: *(h.keyUsage)})
	}
	if h.keyops != nil {
		pairs = append(pairs, &HeaderPair{Key: KeyOpsKey, Value: *(h.keyops)})
	}
	if h.x != nil {
		pairs = append(pairs, &HeaderPair{Key: ECDSAXKey, Value: h.x})
	}
	if h.x509CertChain != nil {
		pairs = append(pairs, &HeaderPair{Key: X509CertChainKey, Value: *(h.x509CertChain)})
	}
	if h.x509CertThumbprint != nil {
		pairs = append(pairs, &HeaderPair{Key: X509CertThumbprintKey, Value: *(h.x509CertThumbprint)})
	}
	if h.x509CertThumbprintS256 != nil {
		pairs = append(pairs, &HeaderPair{Key: X509CertThumbprintS256Key, Value: *(h.x509CertThumbprintS256)})
	}
	if h.x509URL != nil {
		pairs = append(pairs, &HeaderPair{Key: X509URLKey, Value: *(h.x509URL)})
	}
	if h.y != nil {
		pairs = append(pairs, &HeaderPair{Key: ECDSAYKey, Value: h.y})
	}
	for k, v := range h.privateParams {
		pairs = append(pairs, &HeaderPair{Key: k, Value: v})
	}
	return pairs
}

func (h *ecdsaPublicKey) PrivateParams() map[string]interface{} {
	return h.privateParams
}

func (h *ecdsaPublicKey) Get(name string) (interface{}, bool) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	switch name {
	case KeyTypeKey:
		return h.KeyType(), true
	case AlgorithmKey:
		if h.algorithm == nil {
			return nil, false
		}
		return *(h.algorithm), true
	case ECDSACrvKey:
		if h.crv == nil {
			return nil, false
		}
		return *(h.crv), true
	case KeyIDKey:
		if h.keyID == nil {
			return nil, false
		}
		return *(h.keyID), true
	case KeyUsageKey:
		if h.keyUsage == nil {
			return nil, false
		}
		return *(h.keyUsage), true
	case KeyOpsKey:
		if h.keyops == nil {
			return nil, false
		}
		return *(h.keyops), true
	case ECDSAXKey:
		if h.x == nil {
			return nil, false
		}
		return h.x, true
	case X509CertChainKey:
		if h.x509CertChain == nil {
			return nil, false
		}
		return h.x509CertChain.Get(), true
	case X509CertThumbprintKey:
		if h.x509CertThumbprint == nil {
			return nil, false
		}
		return *(h.x509CertThumbprint), true
	case X509CertThumbprintS256Key:
		if h.x509CertThumbprintS256 == nil {
			return nil, false
		}
		return *(h.x509CertThumbprintS256), true
	case X509URLKey:
		if h.x509URL == nil {
			return nil, false
		}
		return *(h.x509URL), true
	case ECDSAYKey:
		if h.y == nil {
			return nil, false
		}
		return h.y, true
	default:
		v, ok := h.privateParams[name]
		return v, ok
	}
}

func (h *ecdsaPublicKey) Set(name string, value interface{}) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.setNoLock(name, value)
}

func (h *ecdsaPublicKey) setNoLock(name string, value interface{}) error {
	switch name {
	case "kty":
		return nil
	case AlgorithmKey:
		switch v := value.(type) {
		case string:
			h.algorithm = &v
		case fmt.Stringer:
			tmp := v.String()
			h.algorithm = &tmp
		default:
			return errors.Errorf(`invalid type for %s key: %T`, AlgorithmKey, value)
		}
		return nil
	case ECDSACrvKey:
		if v, ok := value.(jwa.EllipticCurveAlgorithm); ok {
			h.crv = &v
			return nil
		}
		return errors.Errorf(`invalid value for %s key: %T`, ECDSACrvKey, value)
	case KeyIDKey:
		if v, ok := value.(string); ok {
			h.keyID = &v
			return nil
		}
		return errors.Errorf(`invalid value for %s key: %T`, KeyIDKey, value)
	case KeyUsageKey:
		switch v := value.(type) {
		case KeyUsageType:
			switch v {
			case ForSignature, ForEncryption:
				tmp := v.String()
				h.keyUsage = &tmp
			default:
				return errors.Errorf(`invalid key usage type %s`, v)
			}
		case string:
			h.keyUsage = &v
		default:
			return errors.Errorf(`invalid key usage type %s`, v)
		}
	case KeyOpsKey:
		var acceptor KeyOperationList
		if err := acceptor.Accept(value); err != nil {
			return errors.Wrapf(err, `invalid value for %s key`, KeyOpsKey)
		}
		h.keyops = &acceptor
		return nil
	case ECDSAXKey:
		if v, ok := value.([]byte); ok {
			h.x = v
			return nil
		}
		return errors.Errorf(`invalid value for %s key: %T`, ECDSAXKey, value)
	case X509CertChainKey:
		var acceptor CertificateChain
		if err := acceptor.Accept(value); err != nil {
			return errors.Wrapf(err, `invalid value for %s key`, X509CertChainKey)
		}
		h.x509CertChain = &acceptor
		return nil
	case X509CertThumbprintKey:
		if v, ok := value.(string); ok {
			h.x509CertThumbprint = &v
			return nil
		}
		return errors.Errorf(`invalid value for %s key: %T`, X509CertThumbprintKey, value)
	case X509CertThumbprintS256Key:
		if v, ok := value.(string); ok {
			h.x509CertThumbprintS256 = &v
			return nil
		}
		return errors.Errorf(`invalid value for %s key: %T`, X509CertThumbprintS256Key, value)
	case X509URLKey:
		if v, ok := value.(string); ok {
			h.x509URL = &v
			return nil
		}
		return errors.Errorf(`invalid value for %s key: %T`, X509URLKey, value)
	case ECDSAYKey:
		if v, ok := value.([]byte); ok {
			h.y = v
			return nil
		}
		return errors.Errorf(`invalid value for %s key: %T`, ECDSAYKey, value)
	default:
		if h.privateParams == nil {
			h.privateParams = map[string]interface{}{}
		}
		h.privateParams[name] = value
	}
	return nil
}

func (k *ecdsaPublicKey) Remove(key string) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	switch key {
	case AlgorithmKey:
		k.algorithm = nil
	case ECDSACrvKey:
		k.crv = nil
	case KeyIDKey:
		k.keyID = nil
	case KeyUsageKey:
		k.keyUsage = nil
	case KeyOpsKey:
		k.keyops = nil
	case ECDSAXKey:
		k.x = nil
	case X509CertChainKey:
		k.x509CertChain = nil
	case X509CertThumbprintKey:
		k.x509CertThumbprint = nil
	case X509CertThumbprintS256Key:
		k.x509CertThumbprintS256 = nil
	case X509URLKey:
		k.x509URL = nil
	case ECDSAYKey:
		k.y = nil
	default:
		delete(k.privateParams, key)
	}
	return nil
}

func (k *ecdsaPublicKey) Clone() (Key, error) {
	return cloneKey(k)
}

func (k *ecdsaPublicKey) DecodeCtx() DecodeCtx {
	k.mu.RLock()
	defer k.mu.RUnlock()
	return k.dc
}

func (k *ecdsaPublicKey) SetDecodeCtx(dc DecodeCtx) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.dc = dc
}

func (h *ecdsaPublicKey) UnmarshalJSON(buf []byte) error {
	h.algorithm = nil
	h.crv = nil
	h.keyID = nil
	h.keyUsage = nil
	h.keyops = nil
	h.x = nil
	h.x509CertChain = nil
	h.x509CertThumbprint = nil
	h.x509CertThumbprintS256 = nil
	h.x509URL = nil
	h.y = nil
	dec := json.NewDecoder(bytes.NewReader(buf))
LOOP:
	for {
		tok, err := dec.Token()
		if err != nil {
			return errors.Wrap(err, `error reading token`)
		}
		switch tok := tok.(type) {
		case json.Delim:
			// Assuming we're doing everything correctly, we should ONLY
			// get either '{' or '}' here.
			if tok == '}' { // End of object
				break LOOP
			} else if tok != '{' {
				return errors.Errorf(`expected '{', but got '%c'`, tok)
			}
		case string: // Objects can only have string keys
			switch tok {
			case KeyTypeKey:
				val, err := json.ReadNextStringToken(dec)
				if err != nil {
					return errors.Wrap(err, `error reading token`)
				}
				if val != jwa.EC.String() {
					return errors.Errorf(`invalid kty value for RSAPublicKey (%s)`, val)
				}
			case AlgorithmKey:
				if err := json.AssignNextStringToken(&h.algorithm, dec); err != nil {
					return errors.Wrapf(err, `failed to decode value for key %s`, AlgorithmKey)
				}
			case ECDSACrvKey:
				var decoded jwa.EllipticCurveAlgorithm
				if err := dec.Decode(&decoded); err != nil {
					return errors.Wrapf(err, `failed to decode value for key %s`, ECDSACrvKey)
				}
				h.crv = &decoded
			case KeyIDKey:
				if err := json.AssignNextStringToken(&h.keyID, dec); err != nil {
					return errors.Wrapf(err, `failed to decode value for key %s`, KeyIDKey)
				}
			case KeyUsageKey:
				if err := json.AssignNextStringToken(&h.keyUsage, dec); err != nil {
					return errors.Wrapf(err, `failed to decode value for key %s`, KeyUsageKey)
				}
			case KeyOpsKey:
				var decoded KeyOperationList
				if err := dec.Decode(&decoded); err != nil {
					return errors.Wrapf(err, `failed to decode value for key %s`, KeyOpsKey)
				}
				h.keyops = &decoded
			case ECDSAXKey:
				if err := json.AssignNextBytesToken(&h.x, dec); err != nil {
					return errors.Wrapf(err, `failed to decode value for key %s`, ECDSAXKey)
				}
			case X509CertChainKey:
				var decoded CertificateChain
				if err := dec.Decode(&decoded); err != nil {
					return errors.Wrapf(err, `failed to decode value for key %s`, X509CertChainKey)
				}
				h.x509CertChain = &decoded
			case X509CertThumbprintKey:
				if err := json.AssignNextStringToken(&h.x509CertThumbprint, dec); err != nil {
					return errors.Wrapf(err, `failed to decode value for key %s`, X509CertThumbprintKey)
				}
			case X509CertThumbprintS256Key:
				if err := json.AssignNextStringToken(&h.x509CertThumbprintS256, dec); err != nil {
					return errors.Wrapf(err, `failed to decode value for key %s`, X509CertThumbprintS256Key)
				}
			case X509URLKey:
				if err := json.AssignNextStringToken(&h.x509URL, dec); err != nil {
					return errors.Wrapf(err, `failed to decode value for key %s`, X509URLKey)
				}
			case ECDSAYKey:
				if err := json.AssignNextBytesToken(&h.y, dec); err != nil {
					return errors.Wrapf(err, `failed to decode value for key %s`, ECDSAYKey)
				}
			default:
				if dc := h.dc; dc != nil {
					if localReg := dc.Registry(); localReg != nil {
						decoded, err := localReg.Decode(dec, tok)
						if err == nil {
							h.setNoLock(tok, decoded)
							continue
						}
					}
				}
				decoded, err := registry.Decode(dec, tok)
				if err == nil {
					h.setNoLock(tok, decoded)
					continue
				}
				return errors.Wrapf(err, `could not decode field %s`, tok)
			}
		default:
			return errors.Errorf(`invalid token %T`, tok)
		}
	}
	if h.crv == nil {
		return errors.Errorf(`required field crv is missing`)
	}
	if h.x == nil {
		return errors.Errorf(`required field x is missing`)
	}
	if h.y == nil {
		return errors.Errorf(`required field y is missing`)
	}
	return nil
}

func (h ecdsaPublicKey) MarshalJSON() ([]byte, error) {
	data := make(map[string]interface{})
	fields := make([]string, 0, 11)
	for _, pair := range h.makePairs() {
		fields = append(fields, pair.Key.(string))
		data[pair.Key.(string)] = pair.Value
	}

	sort.Strings(fields)
	buf := pool.GetBytesBuffer()
	defer pool.ReleaseBytesBuffer(buf)
	buf.WriteByte('{')
	enc := json.NewEncoder(buf)
	for i, f := range fields {
		if i > 0 {
			buf.WriteRune(',')
		}
		buf.WriteRune('"')
		buf.WriteString(f)
		buf.WriteString(`":`)
		v := data[f]
		switch v := v.(type) {
		case []byte:
			buf.WriteRune('"')
			buf.WriteString(base64.EncodeToString(v))
			buf.WriteRune('"')
		default:
			if err := enc.Encode(v); err != nil {
				return nil, errors.Wrapf(err, `failed to encode value for field %s`, f)
			}
			buf.Truncate(buf.Len() - 1)
		}
	}
	buf.WriteByte('}')
	ret := make([]byte, buf.Len())
	copy(ret, buf.Bytes())
	return ret, nil
}

func (h *ecdsaPublicKey) Iterate(ctx context.Context) HeaderIterator {
	pairs := h.makePairs()
	ch := make(chan *HeaderPair, len(pairs))
	go func(ctx context.Context, ch chan *HeaderPair, pairs []*HeaderPair) {
		defer close(ch)
		for _, pair := range pairs {
			select {
			case <-ctx.Done():
				return
			case ch <- pair:
			}
		}
	}(ctx, ch, pairs)
	return mapiter.New(ch)
}

func (h *ecdsaPublicKey) Walk(ctx context.Context, visitor HeaderVisitor) error {
	return iter.WalkMap(ctx, h, visitor)
}

func (h *ecdsaPublicKey) AsMap(ctx context.Context) (map[string]interface{}, error) {
	return iter.AsMap(ctx, h)
}
