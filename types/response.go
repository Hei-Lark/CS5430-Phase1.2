package types

type Code int

const (
	OK Code = iota
	FAIL
)

type Response struct {
	Status Code        `json:"status"`
	Val    interface{} `json:"val"`
	UID    string      `json:"uid"`
	// Phase 1.2 Specific
	ServerName       string `json:"servername"`
	Message          []byte `json:"message"`
	EncryptedMessage []byte `json:"encryptedmessage"`
}
