package server

import (
	"crypto/rsa"
	"encoding/json"
	"os"

	"github.com/google/uuid"

	"crypto_utils"
	. "types"
)

var privateKey *rsa.PrivateKey
var publicKey *rsa.PublicKey

var name string
var kvstore map[string]interface{}
var Requests chan NetworkData
var Responses chan NetworkData

var session string    // part 2
var sessionKey []byte // phase 1.2

func init() {
	privateKey = crypto_utils.NewPrivateKey()
	publicKey = &privateKey.PublicKey
	publicKeyBytes := crypto_utils.PublicKeyToBytes(publicKey)
	if err := os.WriteFile("SERVER_PUBLICKEY", publicKeyBytes, 0666); err != nil {
		panic(err)
	}

	name = uuid.NewString()
	kvstore = make(map[string]interface{})
	Requests = make(chan NetworkData)
	Responses = make(chan NetworkData)

	go receiveThenSend()
}

func receiveThenSend() {
	defer close(Responses)

	for request := range Requests {
		Responses <- process(request)
	}
}

// Input: a byte array representing a request from a client.
// Deserializes the byte array into a request and performs
// the corresponding operation. Returns the serialized
// response. This method is invoked by the network.
func process(requestData NetworkData) NetworkData {
	var request Request
	json.Unmarshal(requestData.Payload, &request)
	var response Response
	doOp(&request, &response)
	responseBytes, _ := json.Marshal(response)
	return NetworkData{Payload: responseBytes, Name: name}
}

// Input: request from a client. Returns a response.
// Parses request and handles a switch statement to
// return the corresponding response to the request's
// operation.
func doOp(request *Request, response *Response) {
	response.Status = FAIL

	if session == "" && request.Op == LOGIN {
		doLogin(request, response)
	} else if session == request.UID && session != "" {
		switch request.Op {
		case NOOP:
			// NOTHING
		case CREATE:
			doCreate(request, response)
		case DELETE:
			doDelete(request, response)
		case READ:
			doReadVal(request, response)
		case WRITE:
			doWriteVal(request, response)
		case COPY:
			doCopy(request, response)
		case LOGOUT:
			doLogout(request, response)
		default:
			// struct already default initialized to
			// FAIL status
		}
	}
}

/** begin operation methods **/
// Input: key k, value v, metaval m. Returns a response.
// Sets the value and metaval for key k in the
// key-value store to value v and metavalue m.
func doCreate(request *Request, response *Response) {
	if _, ok := kvstore[request.Key]; !ok {
		kvstore[request.Key] = request.Val
		response.Status = OK
	}
}

// Input: key k. Returns a response. Deletes key from
// key-value store. If key does not exist then take no
// action.
func doDelete(request *Request, response *Response) {
	if _, ok := kvstore[request.Key]; ok {
		delete(kvstore, request.Key)
		response.Status = OK
	}
}

// Input: key k. Returns a response with the value
// associated with key. If key does not exist
// then status is FAIL.
func doReadVal(request *Request, response *Response) {
	if v, ok := kvstore[request.Key]; ok {
		response.Val = v
		response.Status = OK
	}
}

// Input: key k and value v. Returns a response.
// Change value in the key-value store associated
// with key k to value v. If key does not exist
// then status is FAIL.
func doWriteVal(request *Request, response *Response) {
	if _, ok := kvstore[request.Key]; ok {
		kvstore[request.Key] = request.Val
		response.Status = OK
	}
}

// Part 1
// Input: key k and key dk. Returns a response.
// Copy value in key-value store associated with
// key k to key-value store associated with key dk.
// If key(s) does not exist then status is FAIL.
func doCopy(request *Request, response *Response) {
	if v, ok := kvstore[request.Src_key]; ok {
		if _, ok := kvstore[request.Dst_key]; ok {
			kvstore[request.Dst_key] = v
			response.Status = OK
		}
	}
}

// Part 2
// Input: UID i. Returns a response.
// Logs user into server session using associated uid u.
// u cannot be an empty string. If another session already
// exists, then the status is FAIL.
func doLogin(request *Request, response *Response) {
	if session != "" {
		response.Status = FAIL
	}

	// Extract Kcs from {Kcs}Ks
	var encryptedRequest struct {
		EncryptedKcs         []byte `json:"EncryptedKcs`
		FullEncryptedMessage []byte `json:"FullEncryptedMessage"`
	}

	encryptedBytes, ok := request.Val.([]byte)
	if !ok {
		response.Status = FAIL
		response.Val = "Invalid data format."
		return
	}

	err := json.Unmarshal(encryptedBytes, &encryptedRequest)
	if err != nil {
		response.Status = FAIL
		response.Val = "Failed to parse request."
		return
	}

	KSession, err := crypto_utils.DecryptPK(encryptedRequest.EncryptedKcs, privateKey)
	if err != nil {
		response.Status = FAIL
		response.Val = "Failed to decrypt session key."
		return
	}

	// Decrypt {C, U, LOGIN, Kds, nonce, sig} using Kcs
	decryptedMessage, err := crypto_utils.DecryptSK(encryptedRequest.FullEncryptedMessage, KSession)
	if err != nil {
		response.Status = FAIL
		response.Val = "Failed to decrypt message."
		return
	}

	var message struct {
		UID       string    `json:"UID"`
		Command   Operation `json:"Command"`
		Kds       []byte    `json:"Kds"`
		Nonce     []byte    `json:"Nonce"`
		Signature []byte    `json:"Signature"`
	}
	err = json.Unmarshal(decryptedMessage, &message)
	if err != nil {
		response.Status = FAIL
		response.Val = "Failed to parse decrypted message."
		return
	}

	// Use Kds to verify sig & check sig details
	verificationKey, err := crypto_utils.BytesToPublicKey(message.Kds)
	if err != nil {
		response.Status = FAIL
		response.Val = "Failed to convert Kds to public key."
		return
	}

	hashMessage := crypto_utils.Hash(decryptedMessage)
	validSignature := crypto_utils.Verify(message.Signature, hashMessage, verificationKey)
	if !validSignature {
		response.Status = FAIL
		response.Val = "Signature verification failed."
		return
	}

	// Store session details
	sessionKey := KSession
	session = message.UID

	// Build response
	responseStruct := struct {
		UID     string
		Command Operation
		Nonce   []byte
	}{
		UID:     request.UID,
		Command: LOGIN,
		Nonce:   message.Nonce,
	}

	responseBits, _ := json.Marshal(responseStruct)

	// Sign response using server private key
	hashResponse := crypto_utils.Hash(responseBits)
	responseSig := crypto_utils.Sign(hashResponse, privateKey)

	temp := struct {
		Message   []byte
		Signature []byte
	}{
		Message:   responseBits,
		Signature: responseSig,
	}
	tempBytes, _ := json.Marshal(temp)

	// Encrypt with sessionKey
	encryptedResponse := crypto_utils.EncryptSK(tempBytes, sessionKey)

	response.Val = encryptedResponse
	response.Status = OK
}

// Input: none. Returns a response.
// Logs a user out of server session. Client uid and server
// session is returned to empty string. If the client is not
// logged in, then the status is FAIL.
func doLogout(request *Request, response *Response) {
	session = ""
	// Reset session key
	sessionKey = nil
	session = ""
	// Response = OK
	response.Status = OK
}
