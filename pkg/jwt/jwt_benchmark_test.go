package jwt

// func BenchmarkJwt(b *testing.B) {
// 	jwtKey := HmacKey{
// 		ID:        "test",
// 		Algorithm: AlgorithmHS256,
// 		Secret:    test_insecure_secret,
// 	}
// 	jwtProvider, _ := NewProvider(jwtKey, nil)
// 	type payload struct {
// 		Message string
// 	}
// 	claims := payload{Message: "Hello World"}
// 	var parsedClaims payload

// 	b.Run("issue", func(b *testing.B) {
// 		b.ReportAllocs()
// 		b.ResetTimer()
// 		for i := 0; i < b.N; i++ {
// 			_, _ = jwtProvider.NewSignedToken(claims, nil)
// 		}
// 	})

// 	token, _ := jwtProvider.NewSignedToken(claims, nil)

// 	b.Run("verify", func(b *testing.B) {
// 		b.ReportAllocs()
// 		b.ResetTimer()
// 		for i := 0; i < b.N; i++ {
// 			_ = jwtProvider.VerifySignedToken(token, &parsedClaims)
// 		}
// 	})
// }
