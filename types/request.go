package types

type Operation int

const (
	NOOP Operation = iota
	CREATE
	DELETE
	READ
	WRITE
	COPY
	LOGIN
	LOGOUT
)

type Request struct {
	Key     string      `json:"key"`
	Val     interface{} `json:"val"`
	Op      Operation   `json:"op"`
	Src_key string      `json:"src_key"`
	Dst_key string      `json:"dst_key"`
	DKey    string      `json:"dkey"`
	UID     string      `json:"uid"`
	// Phase 1.2
	ClientName       string `json:"clientname"`
	EncryptedKcs     []byte `json:"encryptedkcs"`
	EncryptedMessage []byte `json:"encryptedmessage"`
}
