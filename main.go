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
	length     int
	digits     bool
	symbols    bool
	onlydigits bool
)

const (
	lettersUpper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	lettersLower = "abcdefghijklmnopqrstuvwxyz"
	digitsSet    = "0123456789"
	symbolsSet   = "!@#$%&*_+-=.?"
)

func init() {
	flag.IntVar(&length, "l", 12, "Password length")
	flag.BoolVar(&digits, "d", false, "Generate passwords with digits")
	flag.BoolVar(&symbols, "s", false, "Generate passwords with symbols")
	flag.BoolVar(&onlydigits, "od", false, "Generate passwords with only digits")
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

// parseFlags parses the command line flags
func parseFlags() error {
	flag.Parse()
	if length < 1 {
		return errors.New("length must be greater than zero")
	}
	// Increase or justify upper bound; 4096 is reasonable for safety.
	if length > 4096 {
		return errors.New("length must be less than or equal to 4096")
	}
	// Conflicting flags: onlydigits excludes other classes
	if onlydigits && (digits || symbols) {
		return errors.New("conflicting flags: --onlydigits cannot be combined with -d or -s")
	}
	return nil
}

// generatePassword generates a random password with class guarantees
func generatePassword() (string, error) {
	charset, requiredSets := buildCharset()
	if len(charset) == 0 {
		return "", errors.New("empty charset: enable at least one character class")
	}
	if length < len(requiredSets) {
		return "", fmt.Errorf("length must be at least %d to include all required classes", len(requiredSets))
	}

	// Preselect one rune from each required set to guarantee inclusion
	passwordRunes := make([]rune, 0, length)
	for _, set := range requiredSets {
		r, err := randomRuneFrom(set)
		if err != nil {
			return "", err
		}
		passwordRunes = append(passwordRunes, r)
	}

	// Fill the rest from the full charset
	max := big.NewInt(int64(len(charset)))
	for i := len(passwordRunes); i < length; i++ {
		idx, err := rand.Int(rand.Reader, max)
		if err != nil {
			return "", err
		}
		passwordRunes = append(passwordRunes, charset[idx.Int64()])
	}

	// Secure shuffle so required characters are not all at the beginning
	if err := cryptoShuffle(passwordRunes); err != nil {
		return "", err
	}
	return string(passwordRunes), nil
}

// buildCharset builds the charset to use for the password
// and returns the list of "required" sets to guarantee inclusion.
func buildCharset() ([]rune, [][]rune) {
	// only digits mode
	if onlydigits {
		return []rune(digitsSet), [][]rune{[]rune(digitsSet)}
	}

	var charset []rune
	var requiredSets [][]rune

	// Letters are always included by default
	letters := []rune(lettersUpper + lettersLower)
	charset = append(charset, letters...)
	requiredSets = append(requiredSets, letters) // guarantee at least one letter

	if digits {
		d := []rune(digitsSet)
		charset = append(charset, d...)
		requiredSets = append(requiredSets, d)
	}
	if symbols {
		s := []rune(symbolsSet)
		charset = append(charset, s...)
		requiredSets = append(requiredSets, s)
	}
	return charset, requiredSets
}

// cryptoShuffle performs Fisher–Yates shuffle using crypto/rand
func cryptoShuffle(rs []rune) error {
	for i := len(rs) - 1; i > 0; i-- {
		jBig, err := rand.Int(rand.Reader, big.NewInt(int64(i+1)))
		if err != nil {
			return err
		}
		j := int(jBig.Int64())
		rs[i], rs[j] = rs[j], rs[i]
	}
	return nil
}

func randomRuneFrom(set []rune) (rune, error) {
	n := len(set)
	if n == 0 {
		return 0, errors.New("empty set")
	}
	idx, err := rand.Int(rand.Reader, big.NewInt(int64(n)))
	if err != nil {
		return 0, err
	}
	return set[idx.Int64()], nil
}
