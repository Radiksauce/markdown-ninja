package service

import (
	mathrand "math/rand/v2"
	"time"
)

// func (service *KernelService) FormatCodeHyphen(code string) (ret string) {
// 	codeLength := len(code)
// 	for i := 0; i < codeLength; i += 1 {
// 		if i != 0 && i%4 == 0 {
// 			ret += "-"
// 		}

// 		ret += string(rune(code[i]))
// 	}

// 	return
// }

// sleep to prevent spam and bruteforce
// we use random sleep to also prevent potential timing attacks
func (service *KernelService) SleepAuth() {
	time.Sleep(time.Duration(mathrand.Int64N(100)+100) * time.Millisecond)
}

func (service *KernelService) SleepAuthFailure() {
	time.Sleep(time.Duration(mathrand.Int64N(400)+400) * time.Millisecond)
}
