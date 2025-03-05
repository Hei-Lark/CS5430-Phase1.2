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
var uid string                                        // part 2
var sKey = []byte("12345678901234567890123456789012") // crypto_utils.NewSessionKey() // phase1： assume session key given by server, populate after logging in

var serverPublicKey *rsa.PublicKey

func init() {
	fmt.Println("Session key: " + string(sKey))
	name = uuid.NewString()
	Requests = make(chan NetworkData)
	Responses = make(chan NetworkData)

	// ObtainServerPublicKey()
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
	fmt.Println("client processOp")
	if validateRequest(request) {
		switch request.Op {
		case LOGIN:
			if uid == "" {
				uid = request.UID
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
			fmt.Println("client invalid failure")
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

// requestBytes, _ := json.Marshal(request)
// fmt.Println("client send n recieve")
// var res = NetworkData{Payload: crypto_utils.EncryptSK(requestBytes, sKey), Name: name}.Payload
// var r, _ = crypto_utils.DecryptSK(res, sKey)
// json.Unmarshal(r, &response)

func doOp(request *Request, response *Response) {
	requestBytes, _ := json.Marshal(request)
	var res = sendAndReceive(NetworkData{Payload: crypto_utils.EncryptSK(requestBytes, sKey), Name: name})
	var r, _ = crypto_utils.DecryptSK(res.Payload, sKey)
	json.Unmarshal(r, &response)
}

func sendAndReceive(toSend NetworkData) NetworkData {
	Requests <- toSend
	return <-Responses
}
