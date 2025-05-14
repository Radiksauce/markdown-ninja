package jwt

// var (
// 	test_insecure_secret = "9MfG7mC+dqxXgXZGdiFsxyET1mQRBekiw7K+bIvZEGc="
// )

// func TestVerifyInvalidTokens(t *testing.T) {
// 	jwtKey := HmacKey{
// 		ID:        "test",
// 		Algorithm: AlgorithmHS256,
// 		Secret:    test_insecure_secret,
// 	}
// 	jwtProvider, _ := NewProvider(jwtKey, nil)
// 	invalidTokens := []string{
// 		".",
// 		"..",
// 		"...",
// 		"....",
// 		"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..",
// 		".eyJtZXNzYWdlIjoiOSJ9.",
// 		"..pRVbZ4OC40z7qZsRj0cPpLodPmMAF7-skUqztxeK9iQ=",
// 		"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJtZXNzYWdlIjoiOSJ9.",
// 		".eyJtZXNzYWdlIjoiOSJ9.pRVbZ4OC40z7qZsRj0cPpLodPmMAF7-skUqztxeK9iQ=",
// 		"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..pRVbZ4OC40z7qZsRj0cPpLodPmMAF7-skUqztxeK9iQ=",
// 	}

// 	for _, invalidToken := range invalidTokens {
// 		var decodedPayload struct{}
// 		err := jwtProvider.VerifySignedToken(invalidToken, &decodedPayload)
// 		if err == nil {
// 			t.Errorf("The invalid token: %s is verifed as valid", invalidToken)
// 		}
// 	}
// }

// func TestVerifyKnownJWTs(t *testing.T) {
// 	jwts := []struct {
// 		Token     string
// 		Algorithm Algorithm
// 		Secret    string
// 	}{
// 		{
// 			Token:     "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6InRlc3QifQ.eyJtZXNzYWdlIjoiSGVsbG8gV29ybGQifQ.-S_I4PoZ1PHW_Te50FxDO8gcdvvzQ-gCIY6wQ9QG0sw",
// 			Algorithm: AlgorithmHS256,
// 			Secret:    "secretsecretsecretsecretsecretsecret",
// 		},
// 		{
// 			Token:     "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCIsImtpZCI6InRlc3QifQ.eyJtZXNzYWdlIjoiSGVsbG8gV29ybGQifQ.imRtQ6zon-FEODla3n4ItVsX53So4Wxf3NifNmPz8b1D6s0xBH-v35q_FKM6hvgx-L6IXWcc3Epthg-OMxcIIw",
// 			Algorithm: AlgorithmHS512,
// 			Secret:    "secretsecretsecretsecretsecretsecret",
// 		},
// 	}

// 	for _, knownJwt := range jwts {
// 		var emptyStruct struct{}
// 		jwtKey := HmacKey{
// 			ID:        "test",
// 			Algorithm: knownJwt.Algorithm,
// 			Secret:    knownJwt.Secret,
// 		}
// 		jwtProvider, _ := NewProvider(jwtKey, nil)
// 		err := jwtProvider.VerifySignedToken(knownJwt.Token, &emptyStruct)
// 		if err != nil {
// 			t.Error(err)
// 		}
// 	}
// }

// func TestIssueAndVerify(t *testing.T) {
// 	type claims struct {
// 		Message string `json:"message"`
// 	}
// 	jwtKeys := []HmacKey{
// 		{
// 			ID:        "test_256",
// 			Algorithm: AlgorithmHS256,
// 			Secret:    test_insecure_secret,
// 		},
// 		{
// 			ID:        "test_512",
// 			Algorithm: AlgorithmHS512,
// 			Secret:    test_insecure_secret,
// 		},
// 	}

// 	for _, jwtKey := range jwtKeys {
// 		jwtProvider, _ := NewProvider(jwtKey, nil)

// 		for i := 0; i < 10; i += 1 {
// 			payload := claims{Message: strconv.Itoa(i)}
// 			token, err := jwtProvider.NewSignedToken(payload, nil)
// 			if err != nil {
// 				t.Error(err)
// 			}

// 			var decodedPayload claims
// 			err = jwtProvider.VerifySignedToken(token, &decodedPayload)
// 			if err != nil {
// 				t.Error(err)
// 			}
// 			if decodedPayload.Message != payload.Message {
// 				t.Errorf("payload.message (%s) != decodedPayload.message(%s)", payload.Message, decodedPayload.Message)
// 			}
// 		}
// 	}
// }

// func TestIssueAndVerifyInvalid(t *testing.T) {
// 	type claims struct {
// 		Message string `json:"message"`
// 	}
// 	jwtKey := HmacKey{
// 		ID:        "test",
// 		Algorithm: AlgorithmHS256,
// 		Secret:    test_insecure_secret,
// 	}
// 	jwtProvider, _ := NewProvider(jwtKey, nil)

// 	for i := 0; i < 10; i += 1 {
// 		payload := claims{Message: strconv.Itoa(i)}
// 		token, err := jwtProvider.NewSignedToken(payload, nil)
// 		if err != nil {
// 			t.Error(err)
// 		}

// 		var decodedPayload claims

// 		invalidTokenWithPrefix := "x" + token
// 		err = jwtProvider.VerifySignedToken(invalidTokenWithPrefix, &decodedPayload)
// 		if !errors.Is(err, ErrTokenIsNotValid) {
// 			t.Errorf("expected error: %s. got: %v", ErrTokenIsNotValid, err)
// 		}

// 		invalidTokenWithInvalidPrefix := "|" + token
// 		err = jwtProvider.VerifySignedToken(invalidTokenWithInvalidPrefix, &decodedPayload)
// 		if !errors.Is(err, ErrTokenIsNotValid) {
// 			t.Errorf("expected error: %s. got: %v", ErrTokenIsNotValid, err)
// 		}

// 		invalidTokenWithSuffix := token + "x"
// 		err = jwtProvider.VerifySignedToken(invalidTokenWithSuffix, &decodedPayload)
// 		if !errors.Is(err, ErrSignatureIsNotValid) {
// 			t.Errorf("expected error: %s. got: %v", ErrSignatureIsNotValid, err)
// 		}

// 		invalidTokenWithInvalidSuffix := token + "|"
// 		err = jwtProvider.VerifySignedToken(invalidTokenWithInvalidSuffix, &decodedPayload)
// 		if !errors.Is(err, ErrTokenIsNotValid) {
// 			t.Errorf("expected error: %s. got: %v", ErrTokenIsNotValid, err)
// 		}
// 	}
// }

// func TestIssueAndVerifyExpireIntTheFuture(t *testing.T) {
// 	type claims struct {
// 		Message string `json:"message"`
// 	}
// 	jwtKey := HmacKey{
// 		ID:        "test",
// 		Algorithm: AlgorithmHS256,
// 		Secret:    test_insecure_secret,
// 	}
// 	jwtProvider, _ := NewProvider(jwtKey, nil)

// 	for i := 0; i < 10; i += 1 {
// 		payload := claims{Message: strconv.Itoa(i)}
// 		expiresAt := time.Now().Add(1 * time.Hour)
// 		token, err := jwtProvider.NewSignedToken(payload, &TokenOptions{ExpirationTime: &expiresAt})
// 		if err != nil {
// 			t.Error(err)
// 		}

// 		var decodedPayload claims
// 		err = jwtProvider.VerifySignedToken(token, &decodedPayload)
// 		if err != nil {
// 			t.Error(err)
// 		}
// 		if decodedPayload.Message != payload.Message {
// 			t.Errorf("pyaload.message (%s) != decodedPayload.message(%s)", payload.Message, decodedPayload.Message)
// 		}
// 	}
// }

// func TestIssueAndVerifyExpired(t *testing.T) {
// 	type emptyClaims struct {
// 	}
// 	type claims struct {
// 		Message string `json:"message"`
// 	}
// 	jwtKey := HmacKey{
// 		ID:        "test",
// 		Algorithm: AlgorithmHS256,
// 		Secret:    test_insecure_secret,
// 	}
// 	jwtProvider, _ := NewProvider(jwtKey, nil)

// 	for i := 0; i < 10; i += 1 {
// 		expiresAt := time.Now().Add(-1 * time.Hour)
// 		token, err := jwtProvider.NewSignedToken(emptyClaims{}, &TokenOptions{ExpirationTime: &expiresAt})
// 		if err != nil {
// 			t.Error(err)
// 		}

// 		var decodedPayload emptyClaims
// 		err = jwtProvider.VerifySignedToken(token, &decodedPayload)
// 		if !errors.Is(err, ErrTokenHasExpired) {
// 			t.Errorf("expected error: %s. got: %v", ErrTokenHasExpired, err)
// 		}
// 	}

// 	for i := 0; i < 10; i += 1 {
// 		payload := claims{Message: strconv.Itoa(i)}
// 		expiresAt := time.Now().Add(-1 * time.Hour)
// 		token, err := jwtProvider.NewSignedToken(payload, &TokenOptions{ExpirationTime: &expiresAt})
// 		if err != nil {
// 			t.Error(err)
// 		}

// 		var decodedPayload claims
// 		err = jwtProvider.VerifySignedToken(token, &decodedPayload)
// 		if !errors.Is(err, ErrTokenHasExpired) {
// 			t.Errorf("expected error: %s. got: %v", ErrTokenHasExpired, err)
// 		}
// 	}
// }
