package main

import (
	"flag"
	"fmt"
)

var (
	opt               string
	bits              int
	output            string
	publicPath        string
	privatePath       string
	signature         string
	message           string
	timeTransformType string
	timeStamp         int64
)

const (
	Gen        = "gen"
	Sign       = "sign"
	Verify     = "verify"
	Time       = "time"
	UnixToTime = "unixStampToTime"
)

func main() {
	flag.IntVar(&bits, "b", 2048, "the length of key, default 2048 bits")
	flag.StringVar(&output, "o", "rsa", "output dir, default 'rsa'")
	flag.StringVar(&opt, "opt", "", "option: 'gen','sign','verify','time'")
	flag.StringVar(&publicPath, "pub", "rsa/public.pem", "the path of public key, default 'rsa/public.pem'")
	flag.StringVar(&privatePath, "private", "rsa/private.pem", "the path of private key, default 'rsa/public.pem'")
	flag.StringVar(&signature, "sign", "", "signature")
	flag.StringVar(&message, "message", "", "the message for signature or verify")
	flag.StringVar(&timeTransformType, "timeTransformType", "unixStampToTime", "time transform type")
	flag.Int64Var(&timeStamp, "time", 0, "source time")
	flag.Parse()
	switch opt {
	case Gen:
		gen()
	case Sign:
		sign()
	case Verify:
		verify()
	case Time:
		timeProcess()
	default:
		fmt.Println("invalid opt")
	}
}
func gen() {
	if err := GenRSAKey(output, bits); err != nil {
		fmt.Errorf("%v", err)
	}
}
func sign() {
	res, err := SignByRSA(privatePath, message)
	if err != nil {
		fmt.Errorf("%v", err)
	}
	fmt.Printf("%v\n", res)
}

func verify() {
	success, err := VerifySignature(publicPath, signature, message)
	if err != nil {
		fmt.Errorf("%v", err)
	}
	fmt.Printf("%v\n", success)
}

func timeProcess() {
	switch timeTransformType {
	case UnixToTime:
		t := UnixStampToTime(timeStamp)
		fmt.Printf("src: %v, dst: %v", timeStamp, t)
	}
}
