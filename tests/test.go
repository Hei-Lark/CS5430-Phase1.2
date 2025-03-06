package main

import (
	"encoding/json"
	"fmt"

	"crypto_utils"
	. "types"
)

var Requests chan NetworkData
var Responses chan NetworkData
var sessionKey []byte
var name string

func main() {
	fmt.Println("start tests here")
	sessionKey = crypto_utils.NewSessionKey()
	// send utter garbage to server
	var r = sendAndReceive(NetworkData{Payload: crypto_utils.RandomBytes(32), Name: "trudy"})
	fmt.Println("Test 1: ", r)

	// send command to server with wrong session Key
	var vBytes, _ = json.Marshal(2)
	request := &Request{
		Val: vBytes,
		Op:  CREATE,
		UID: "uid",
	}
	requestBytes, _ := json.Marshal(request)
	var res = sendAndReceive(NetworkData{Payload: crypto_utils.EncryptSK(requestBytes, sessionKey), Name: "trudy"})
	fmt.Println("Test 2 undecrypted: ", res)
	var n, _ = crypto_utils.DecryptSK(res.Payload, sessionKey)
	fmt.Println("Test 2 decrypted: ", n)
}

// for sending / recieving clientside
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

// for sending / recieving serverside
func receiveThenSend(payload NetworkData) {
	defer close(Responses)

	Responses <- payload
}
