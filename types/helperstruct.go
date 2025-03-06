package types

// to ensure correct JSON unmarshaling for []byte type
// helper struct that can be used to ensure that the byte arrays remain byte arrays during unmarshaling
type HelperStruct struct {
	Val []byte    `json:"val"`
	Op  Operation `json: "op"`
	UID string    `json:"uid`
}
