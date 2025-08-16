package main

import (
	"crypto/rand"
	"errors"
	"flag"
	"fmt"
	"log"
	"math/big"
)

var (
	length    int
	digits    bool
	symbols   bool
	lowercase bool
	uppercase bool
)

func init() {
	flag.IntVar(&length, "length", 12, "Password length")
	flag.BoolVar(&digits, "digits", false, "Generate passwords with digits")
	flag.BoolVar(&symbols, "symbols", false, "Generate passwords with symbols")
	flag.BoolVar(&lowercase, "lowercase", true, "Generate passwords with lowercase")
	flag.BoolVar(&uppercase, "uppercase", true, "Generate passwords with uppercase")
}

func main() {
	err := parseFlags()
	if err != nil {
		log.Fatal(err)
	}
	password, err := generatePassword()
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println("Password:", password)
}

func parseFlags() error {
	flag.Parse()
	if length < 1 {
		return errors.New("length must be greater than zero")
	}
	if length > 200 {
		return errors.New("length must be less than 200")
	}
	return nil
}

func generatePassword() (string, error) {
	password := make([]rune, 0, length)
	charset, err := buildCharset()
	if err != nil {
		return "", err
	}
	for i := 0; i < length; i++ {
		idx, err := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
		if err != nil {
			return "", err
		}
		password = append(password, charset[idx.Int64()])
	}
	return string(password), nil
}

func buildCharset() ([]rune, error) {
	var charset []rune
	if lowercase {
		charset = append(charset, []rune("abcdefghijklmnopqrstuvwxyz")...)
	}
	if uppercase {
		charset = append(charset, []rune("ABCDEFGHIJKLMNOPQRSTUVWXYZ")...)
	}
	if digits {
		charset = append(charset, []rune("0123456789")...)
	}
	if symbols {
		charset = append(charset, []rune("!@#$%&*_+-=.?")...)
	}
	if len(charset) == 0 {
		return nil, errors.New("error: all character types are disabled. " +
			"Add at least one or do not disable flags -lowercase or -uppercase")
	}
	return charset, nil
}
