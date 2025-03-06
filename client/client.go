package client

import (
	"crypto/rsa"
	"encoding/json"
	"fmt"
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

			// Generate pub/priv key pair
			clientPrivKey = crypto_utils.NewPrivateKey()
			clientPubKey = &clientPrivKey.PublicKey

			// Generate signing keys
			EncryptionSigningKey = crypto_utils.NewPrivateKey()
			EncryptionVerificationKey = &EncryptionSigningKey.PublicKey

			// Get server public key Ks
			ObtainServerPublicKey()

			// Generate session key Kcs on startup
			sessionKey = crypto_utils.NewSessionKey()

			if uid == "" {
				uid = request.UID
			} else {
				request.UID = uid
			}

			// Generate pub/priv key pair
			clientPrivKey = crypto_utils.NewPrivateKey()
			clientPubKey = &clientPrivKey.PublicKey

			// Generate signing keys
			EncryptionSigningKey = crypto_utils.NewPrivateKey()
			EncryptionVerificationKey = &EncryptionSigningKey.PublicKey

			// Get server public key Ks
			ObtainServerPublicKey()

			// Generate session key Kcs on startup
			sessionKey = crypto_utils.NewSessionKey()

			// Encrypt Kcs with Ks
			EncryptedKcs := crypto_utils.EncryptPK(sessionKey, serverPublicKey)

			// Generate nonce
			// nonce := crypto_utils.RandomBytes(4)

			// Create message bits
			messageStruct := struct {
				UID     string
				Command Operation
				// Kc      []byte
				Kds []byte
				// Nonce   []byte
			}{
				UID:     uid,
				Command: LOGIN,
				// Kc:      crypto_utils.PublicKeyToBytes(clientPubKey),
				Kds: crypto_utils.PublicKeyToBytes(EncryptionVerificationKey),
				// Nonce:   nonce,
			}
			messageBits, _ := json.Marshal(messageStruct)

			// Create signature
			hashMessage := crypto_utils.Hash(messageBits)
			signature := crypto_utils.Sign(hashMessage, EncryptionSigningKey)

			// Create (m, sig)Kcs
			messageAndSignatureStruct := struct {
				Message   []byte
				Signature []byte
			}{
				Message:   messageBits,
				Signature: signature,
			}

			// Encrypted with Kcs
			messageAndSignature, _ := json.Marshal(messageAndSignatureStruct)
			messageAndSigEncrypted := crypto_utils.EncryptSK(messageAndSignature, sessionKey)

			// Construct final message: {Kcs}Ks, {(message, sig)}Kcs
			finalStruct := struct {
				EncryptedKcs         []byte
				FullEncryptedMessage []byte
			}{
				EncryptedKcs:         EncryptedKcs,
				FullEncryptedMessage: messageAndSigEncrypted,
			}

			// Final Bytes
			finalBytes, _ := json.Marshal(finalStruct)

			// Construct Request
			request := &Request{
				Val: finalBytes,
				Op:  LOGIN,
				UID: uid,
			}

			fmt.Println("req")
			fmt.Println(request)

			doOp(request, response)

		case CREATE, DELETE, READ, WRITE, COPY:
			request.UID = uid
			doOpS(request, response)
		case LOGOUT:
			if uid == "" {
				// If no user is logged in, return an error or handle it
				response.Status = FAIL
				response.Val = "No user is logged in."
				break
			}

			// Generate nonce
			// nonce := crypto_utils.RandomBytes(4)

			logoutMessageStruct := struct {
				UID     string
				Command Operation
				// Nonce   []byte
			}{
				UID:     uid,
				Command: LOGOUT,
				// Nonce:   nonce,
			}

			messageBytes, _ := json.Marshal(logoutMessageStruct)

			// Create signature
			messageHash := crypto_utils.Hash(messageBytes)
			signature := crypto_utils.Sign(messageHash, EncryptionSigningKey)

			temp := struct {
				Message   []byte
				Signature []byte
			}{
				Message:   messageBytes,
				Signature: signature,
			}

			// concatenate message + signature
			messageAndSignature, _ := json.Marshal(temp)
			messageAndSigEncrypted := crypto_utils.EncryptSK(messageAndSignature, sessionKey)

			finalStruct := struct {
				FullEncryptedMessage []byte
			}{
				FullEncryptedMessage: messageAndSigEncrypted,
			}

			finalBytes, _ := json.Marshal(finalStruct)

			// set Val field to byte array
			request := &Request{
				Val: finalBytes,
				Op:  LOGOUT,
				UID: uid,
			}

			doOp(request, response)

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

	// Force []byte type on the requestBytes
	// Prevent unmarshaling problems
	helper := &HelperStruct{
		Data:    requestBytes,
		Command: LOGIN,
		UserID:  uid,
	}

	helperBytes, _ := json.Marshal(helper)

	serverResponse := sendAndReceive(NetworkData{Payload: helperBytes, Name: name})

	var encryptedResponse struct {
		Message   []byte
		Signature []byte
	}

	err := json.Unmarshal(serverResponse.Payload, &encryptedResponse)
	if err != nil {
		response.Status = FAIL
		response.Val = "Failed to parse server response."
		return
	}
	fmt.Println(encryptedResponse.Message)

	decryptedMessage, err := crypto_utils.DecryptSK(encryptedResponse.Message, sessionKey)
	if err != nil {
		response.Status = FAIL
		response.Val = "Failed to decrypt server response."
		return
	}

	msgHash := crypto_utils.Hash(decryptedMessage)

	validSignature := crypto_utils.Verify(encryptedResponse.Signature, msgHash, serverPublicKey)
	if !validSignature {
		response.Status = FAIL
		response.Val = "Signature verification failed."
		return
	}

	err = json.Unmarshal(decryptedMessage, response)
	if err != nil {
		response.Status = FAIL
		response.Val = "Failed to parse decrypted message into response."
		return
	}

	// Clear Client Info
	if response.Status == OK && request.Op == LOGOUT {
		uid = ""                                            // Clear the UID
		sessionKey = nil                                    // Clear the session key
		clientPrivKey = crypto_utils.NewPrivateKey()        // Clear the private client key
		clientPubKey = &clientPrivKey.PublicKey             // Clear the public client key
		EncryptionSigningKey = crypto_utils.NewPrivateKey() // Clear the encryption signing key
		EncryptionVerificationKey = &EncryptionSigningKey.PublicKey
	}

	response.Status = OK

	//json.Unmarshal(sendAndReceive(NetworkData{Payload: requestBytes, Name: name}).Payload, &response)
}

func doOpS(request *Request, response *Response) {
	requestBytes, _ := json.Marshal(request)
	var res = sendAndReceive(NetworkData{Payload: crypto_utils.EncryptSK(requestBytes, sessionKey), Name: name})
	var r, _ = crypto_utils.DecryptSK(res.Payload, sessionKey)
	json.Unmarshal(r, &response)
}

func sendAndReceive(toSend NetworkData) NetworkData {
	Requests <- toSend
	return <-Responses
}
