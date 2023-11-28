package common

// DmVerity contains information about the hash device and dm-verity root hash to open the encrypted fs with dm-verity protection
type DmVerity struct {
	Enable bool `json:"enable,omitempty"`
	HashUrl string `json:"hash_url,omitemtpy"`
	RootHash string `json:"root_hash,omitemtpy"`
}