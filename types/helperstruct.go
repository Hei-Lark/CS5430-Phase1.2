package types

// to ensure correct JSON unmarshaling for []byte type
type HelperStruct struct {
	Data    []byte    `json:"data"`
	Command Operation `json: "command"`
	UserID  string    `json:"userid`
}
