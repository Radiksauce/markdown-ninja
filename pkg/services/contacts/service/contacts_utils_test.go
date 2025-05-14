package service

// func TestGenerateUnsubscribeToken(t *testing.T) {
// 	var emptyArray [crypto.Size256]byte

// 	for i := 0; i < 100; i += 1 {
// 		contactID := guid.NewTimeBased()
// 		var contactMasterKey [crypto.Size256]byte

// 		_, err := rand.Read(contactMasterKey[:])
// 		if err != nil {
// 			t.Errorf("generating maskter key: %s", err.Error())
// 		}

// 		unsubscribeToken, err := generateUnsubscribeToken(contactID, contactMasterKey)
// 		if err != nil {
// 			return
// 		}

// 		if len(unsubscribeToken) != crypto.Size256 {
// 			t.Errorf("unsubscribeToken bad size. Got: %d | expected: %d", len(unsubscribeToken), crypto.Size256)
// 		}

// 		if bytes.Equal(emptyArray[:], unsubscribeToken) {
// 			t.Error("unsubscribeToken is empty")
// 		}
// 	}
// }

// func TestGenerateUpdateEmailToken(t *testing.T) {
// 	var emptyArray [crypto.Size256]byte

// 	for i := 0; i < 100; i += 1 {
// 		contactID := guid.NewTimeBased()
// 		var contactMasterKey [crypto.Size256]byte
// 		email := fmt.Sprintf("email%d@example.com", i)

// 		_, err := rand.Read(contactMasterKey[:])
// 		if err != nil {
// 			t.Errorf("generating maskter key: %s", err.Error())
// 		}

// 		updateEmailToken, err := generateUpdateEmailToken(contactID, contactMasterKey, email)
// 		if err != nil {
// 			return
// 		}

// 		if len(updateEmailToken) != crypto.Size256 {
// 			t.Errorf("updateEmailToken bad size. Got: %d | expected: %d", len(updateEmailToken), crypto.Size256)
// 		}

// 		if bytes.Equal(emptyArray[:], updateEmailToken) {
// 			t.Error("updateEmailToken is empty")
// 		}
// 	}
// }
