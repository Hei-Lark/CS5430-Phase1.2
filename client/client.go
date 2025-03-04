package client

import (
	"crypto/rsa"
	"encoding/json"
	"os"

	"github.com/google/uuid"

	"crypto_utils"
	. "types"
)

var name string
var Requests chan NetworkData
var Responses chan NetworkData
var uid string // part 2

// added for 1.2
var serverPublicKey *rsa.PublicKey
var clientPrivKey *rsa.PrivateKey
var clientPubKey *rsa.PublicKey
var EncryptionSigningKey *rsa.PrivateKey
var EncryptionVerificationKey *rsa.PublicKey
var sessionKey []byte

func init() {
	name = uuid.NewString()
	Requests = make(chan NetworkData)
	Responses = make(chan NetworkData)

	// Generate pub/priv key pair
	clientPrivKey = crypto_utils.NewPrivateKey()
	clientPubKey = &clientPrivKey.PublicKey

	// Generate signing keys
	EncryptionSigningKey = crypto_utils.NewPrivateKey()
	EncryptionVerificationKey = crypto_utils.NewPrivateKey()

	// Get server public key Ks
	ObtainServerPublicKey()

	// Generate session key Kcs
	sessionKey = crypto_utils.NewSessionKey()

}

func ObtainServerPublicKey() {
	serverPublicKeyBytes, err := os.ReadFile("SERVER_PUBLICKEY")
	if err != nil {
		panic(err)
	}
	serverPublicKey, err = crypto_utils.BytesToPublicKey(serverPublicKeyBytes)
	if err != nil {
		panic(err)
	}
}

func ProcessOp(request *Request) *Response {
	response := &Response{Status: FAIL}
	if validateRequest(request) {
		switch request.Op {
		case LOGIN:
			if uid == "" {
				uid = request.UID

				// Encrypt Kcs with Ks
				EncryptedKcs := crypto_utils.EncryptPK(sessionKey, serverPublicKey)

				// Generate nonce
				nonce := crypto_utils.RandomBytes(4)

				// Create message bits
				messageStruct := struct {
					ClientName string
					UID        string
					Command    Operation
					Kds        []byte
					Nonce      []byte
				}{
					ClientName: name,
					UID:        uid,
					Command:    LOGIN,
					Kds:        crypto_utils.PublicKeyToBytes(EncryptionVerificationKey),
					Nonce:      nonce,
				}
				messageBits, _ := json.Marshal(messageStruct)

				// Create signature
				hashMessage := crypto_utils.Hash(messageBits)
				signature := crypto_utils.Sign(hashMessage, EncryptionSigningKey)

				// Encrypt message with Kcs
				finalMsgNotEncrypted := append(messageBits, signature...)
				finalMsgEncrypted := crypto_utils.EncryptSK(finalMsgNotEncrypted, sessionKey)

				// Form request
				request.ClientName = name
				request.EncryptedKcs = EncryptedKcs
				request.EncryptedMessage = finalMsgEncrypted

				doOp(request, response)

			} else {
				request.UID = uid
			}
		case CREATE, DELETE, READ, WRITE, COPY:
			request.UID = uid
			doOp(request, response)
		case LOGOUT:
			request.UID = uid
			doOp(request, response)
			uid = ""
		default:
			// struct already default initialized to
			// FAIL status
		}
	}
	response.UID = request.UID
	return response
}

func validateRequest(r *Request) bool {
	switch r.Op {
	case CREATE, WRITE:
		return r.Key != "" && r.Val != nil
	case DELETE, READ:
		return r.Key != ""
	case COPY:
		return r.Src_key != "" && r.Dst_key != ""
	case LOGIN:
		return r.UID != ""
	case LOGOUT:
		return uid != ""
	default:
		return false
	}
}

func doOp(request *Request, response *Response) {
	requestBytes, _ := json.Marshal(request)
	json.Unmarshal(sendAndReceive(NetworkData{Payload: requestBytes, Name: name}).Payload, &response)
}

func sendAndReceive(toSend NetworkData) NetworkData {
	Requests <- toSend
	return <-Responses
}
