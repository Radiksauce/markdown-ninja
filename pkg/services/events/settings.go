package events

type SettingAnonymousIDSalt struct {
	Salt string `json:"salt"`
}

func (setting SettingAnonymousIDSalt) Key() string {
	return "events.anonymous_id_salt"
}
