package client

// CS 161 Project 2

// You MUST NOT change these default imports. ANY additional imports
// may break the autograder!

import (
	"encoding/json"

	userlib "github.com/cs161-staff/project2-userlib"
	"github.com/google/uuid"

	// hex.EncodeToString(...) is useful for converting []byte to string

	// Useful for string manipulation
	"strings"

	// Useful for formatting strings (e.g. `fmt.Sprintf`).
	"fmt"

	// Useful for creating new error messages to return using errors.New("...")
	"errors"

	// Optional.
	_ "strconv"
)

// This serves two purposes: it shows you a few useful primitives,
// and suppresses warnings for imports not being used. It can be
// safely deleted!
func someUsefulThings() {

	// Creates a random UUID.
	randomUUID := uuid.New()

	// Prints the UUID as a string. %v prints the value in a default format.
	// See https://pkg.go.dev/fmt#hdr-Printing for all Golang format string flags.
	userlib.DebugMsg("Random UUID: %v", randomUUID.String())

	// Creates a UUID deterministically, from a sequence of bytes.
	hash := userlib.Hash([]byte("user-structs/alice"))
	deterministicUUID, err := uuid.FromBytes(hash[:16])
	if err != nil {
		// Normally, we would `return err` here. But, since this function doesn't return anything,
		// we can just panic to terminate execution. ALWAYS, ALWAYS, ALWAYS check for errors! Your
		// code should have hundreds of "if err != nil { return err }" statements by the end of this
		// project. You probably want to avoid using panic statements in your own code.
		panic(errors.New("An error occurred while generating a UUID: " + err.Error()))
	}
	userlib.DebugMsg("Deterministic UUID: %v", deterministicUUID.String())

	// Declares a Course struct type, creates an instance of it, and marshals it into JSON.
	type Course struct {
		name      string
		professor []byte
	}

	course := Course{"CS 161", []byte("Nicholas Weaver")}
	courseBytes, err := json.Marshal(course)
	if err != nil {
		panic(err)
	}

	userlib.DebugMsg("Struct: %v", course)
	userlib.DebugMsg("JSON Data: %v", courseBytes)

	// Generate a random private/public keypair.
	// The "_" indicates that we don't check for the error case here.
	var pk userlib.PKEEncKey
	var sk userlib.PKEDecKey
	pk, sk, _ = userlib.PKEKeyGen()
	userlib.DebugMsg("PKE Key Pair: (%v, %v)", pk, sk)

	// Here's an example of how to use HBKDF to generate a new key from an input key.
	// Tip: generate a new key everywhere you possibly can! It's easier to generate new keys on the fly
	// instead of trying to think about all of the ways a key reuse attack could be performed. It's also easier to
	// store one key and derive multiple keys from that one key, rather than
	originalKey := userlib.RandomBytes(16)
	derivedKey, err := userlib.HashKDF(originalKey, []byte("mac-key"))
	if err != nil {
		panic(err)
	}
	userlib.DebugMsg("Original Key: %v", originalKey)
	userlib.DebugMsg("Derived Key: %v", derivedKey)

	// A couple of tips on converting between string and []byte:
	// To convert from string to []byte, use []byte("some-string-here")
	// To convert from []byte to string for debugging, use fmt.Sprintf("hello world: %s", some_byte_arr).
	// To convert from []byte to string for use in a hashmap, use hex.EncodeToString(some_byte_arr).
	// When frequently converting between []byte and string, just marshal and unmarshal the data.
	//
	// Read more: https://go.dev/blog/strings

	// Here's an example of string interpolation!
	_ = fmt.Sprintf("%s_%d", "file", 1)
}

// This is the type definition for the User struct.
// A Go struct is like a Python or Java class - it can have attributes
// (e.g. like the Username attribute) and methods (e.g. like the StoreFile method below).
type User struct {
	Username string
	Salts map[string]([]byte)
	EncKeys map[string]([]byte)
	Stored map[string]([]byte)
	PasswordHash []byte
	UserMAC []byte //, KeyUUID string
	// You can add other attributes here if you want! But note that in order for attributes to
	// be included when this struct is serialized to/from JSON, they must be capitalized.
	// On the flipside, if you have an attribute that you want to be able to access from
	// this struct's methods, but you DON'T want that value to be included in the serialized value
	// of this struct that's stored in datastore, then you can use a "private" variable (e.g. one that
	// begins with a lowercase letter).
}

type TreeNode struct {

}

type KeyStruct struct {
	Keys map[string]([]byte)
}

type File struct {
	IsFile bool
	IsSentinel bool
	Next *File
	Last *File
	OwnerKeys map[string]([]byte)
	SharedKeys map[string]([]byte)
	Filename, Contents, MAC []byte
	//ShareTree string
}

// NOTE: The following methods have toy (insecure!) implementations.

func InitUser(username string, password string) (userdataptr *User, err error) {
	//check if the user exists in the datastore or is empty
	//TODO RSA STUFF

	//create a user struct
	var userdata User
	userdata.Username = username //Might have to encrypt this
	userdata.Salts = make(map[string]([]byte))
	userdata.EncKeys = make(map[string]([]byte))
	userdata.Stored = make(map[string]([]byte))
	generateUserSalts(&userdata)
	generateUserKeys(&userdata, []byte(password))

	salt := userdata.Salts["userMAC"]
	key := userlib.Argon2Key([]byte(password), salt, uint32(16))
	enc := userdata.EncKeys["userMAC"]
	macKey := userlib.SymDec(key, enc)
	combined := combineUserData(&userdata)
	userdata.UserMAC, _ = userlib.HMACEval(macKey, combined)

	//add salt
	userdata.PasswordHash = userlib.Hash([]byte(password + string(userdata.Salts["password"])))

	nameHash := userlib.Hash([]byte(username))
	id, _ := uuid.FromBytes(nameHash[:16])
	serial, _ := json.Marshal(userdata)
	userlib.DatastoreSet(id, serial)

	return &userdata, nil
}

func combineUserData(userdata *User) []byte {
	salts := userdata.Salts
	keys := userdata.EncKeys
	var combined string = ""
	names := [12]string  {"file", "filename", "fileMac", "fileKey", "treeKey", "treeMac", "fileLocKey", "RSAFile", "RSAMac", "RSAFilename", "RSATreeNode", "userMAC"}

	for _, val := range names {
		salt := salts[val]
		enc := keys[val]
		combined += (string(salt) + string(enc))
	}

	combined += string(salts["password"])

	return []byte(combined)

}
func generateUserSalts(userdata *User) {
	salts := userdata.Salts
	names := [13]string  {"file", "filename", "fileMac", "fileKey", "treeKey", "treeMac", "fileLocKey", "RSAFile", "RSAMac", "RSAFilename", "RSATreeNode", "userMAC", "password"}
	set := make(map[string]bool)

	for _, val := range names {
		salt := userlib.RandomBytes(8)
		for set[val] != true {
			salt = userlib.RandomBytes(8)
		}
		set[string(salt[:])] = true
		salts[val] = salt
	}
}

func generateUserKeys(userdata *User, password []byte) {
	salts := userdata.Salts
	keys := userdata.EncKeys
	names := [12]string  {"file", "filename", "fileMac", "fileKey", "treeKey", "treeMac", "fileLocKey", "RSAFile", "RSAMac", "RSAFilename", "RSATreeNode", "UserMAC"}
	keyLen := 16

	for _, val := range names {
		key := userlib.Argon2Key(password, userlib.RandomBytes(16), uint32(keyLen))
		salt := salts[val]
		enc := userlib.Argon2Key(password, salt, uint32(keyLen))
		key = userlib.SymEnc(enc, userlib.RandomBytes(16), key)
		keys[val] = key
	}
}

// func generateRSAKeys(keys *map[string]string) {

// }

func GetUser(username string, password string) (userdataptr *User, err error) {
	//TODO MAKE SURE IT EXIST
	var userdata User
	nameHash := userlib.Hash([]byte(username))
	id, _ := uuid.FromBytes(nameHash[:16])
	data, ok := userlib.DatastoreGet(id)
	if !ok {
		//error
	}
	json.Unmarshal(data, &userdata)

	mac1 := userdata.UserMAC
	salt := userdata.Salts["userMAC"]
	key := userlib.Argon2Key([]byte(password), salt, uint32(16))
	enc := userdata.EncKeys["userMAC"]
	macKey := userlib.SymDec(key, enc)
	combined := combineUserData(&userdata)
	mac2, _ := userlib.HMACEval(macKey, combined)
	validMAC := userlib.HMACEqual(mac1, mac2)
	if !validMAC {
		//error
	}

	//Password check
	passHash := userlib.Hash([]byte(password + string(userdata.Salts["password"])))
	hashOk := userlib.HMACEqual(passHash, userdata.PasswordHash)
	if !hashOk {
		//error
	}

	//Unpack values
	unpackUserValues(&userdata, password)
	//return
	return &userdata, nil
}

func unpackUserValues(userdata *User, password string) {
	names := [12]string  {"file", "filename", "fileMac", "fileKey", "treeKey", "treeMac", "fileLocKey", "RSAFile", "RSAMac", "RSAFilename", "RSATreeNode", "UserMAC"}
	for _, val := range names {
		salt := userdata.Salts[val]
		key := userlib.Argon2Key([]byte(password), salt, uint32(16))
		enc := userdata.EncKeys[val]
		store := userlib.SymDec(key, enc)
		userdata.Stored[val] = store
	}
}

func (userdata *User) StoreFile(filename string, content []byte) (err error) {
	var filedata File
	filedata.OwnerKeys = make(map[string]([]byte))
	filedata.SharedKeys = make(map[string]([]byte))
	//generate the file keys
	generateFileKeys(userdata, &filedata)
	//encrypt the contents and filename
	key := userdata.Stored["file"]
	fileKey := userlib.SymDec(key, filedata.OwnerKeys["contents"])
	enc := userlib.SymEnc(fileKey, userlib.RandomBytes(16), content)
	filedata.Contents = enc

	key = userdata.Stored["filename"]
	nameKey := userlib.SymDec(key, filedata.OwnerKeys["filename"])
	enc = userlib.SymEnc(nameKey, userlib.RandomBytes(16), ([]byte)(filename))
	filedata.Filename = enc
	//calculate the mac
	fileValues := unpackFileValues(&filedata)
	key = userdata.Stored["mac"]
	macKey := userlib.SymDec(key, filedata.OwnerKeys["fileMac"])
	enc = userlib.SymEnc(macKey, userlib.RandomBytes(16), fileValues)
	filedata.MAC, _ = userlib.HMACEval(macKey, fileValues)
	//generate uuid
	loc := userdata.Username + filename
	locHash := userlib.Hash([]byte(loc))
	id, _ := uuid.FromBytes(locHash[:16])
	serial, _ := json.Marshal(filedata)
	userlib.DatastoreSet(id, serial)

	//datastore
	return nil
}

func generateFileKeys(userdata *User, filedata *File) {
	names := [3]string {"contents", "mac", "filename"}
	keys := [3]string{"file", "fileMac", "filename"}
	//choose a key and turn it to 6
	key := userdata.Stored["file"]
	reason := []byte("generate file keys")
	derived, _ := userlib.HashKDF(key, reason)
	for i, val := range names {
		key := userdata.Stored[keys[i]]
		slice := derived[i * 16: i * 16 + 16]
		filedata.OwnerKeys[val] = userlib.SymEnc(key, userlib.RandomBytes(16), slice)
	}

}

func unpackFileValues(filedata *File) ([]byte) {
	data := ""
	names := [3]string {"contents", "mac", "filename"}
	for _, val := range names {
		owner := filedata.OwnerKeys[val]
		//shared := filedata.SharedKeys
		data += string(owner) //+ string(shared) 
	}
	data += string(filedata.Filename) + string(filedata.Contents) + string(filedata.MAC)
	return []byte(data)
}

func (userdata *User) AppendToFile(filename string, content []byte) error {
	return nil
}

func (userdata *User) LoadFile(filename string) (content []byte, err error) {
	storageKey, err := uuid.FromBytes(userlib.Hash([]byte(filename + userdata.Username))[:16])
	if err != nil {
		return nil, err
	}
	dataJSON, ok := userlib.DatastoreGet(storageKey)
	if !ok {
		return nil, errors.New(strings.ToTitle("file not found"))
	}
	err = json.Unmarshal(dataJSON, &content)
	return content, err
}

func (userdata *User) CreateInvitation(filename string, recipientUsername string) (
	invitationPtr uuid.UUID, err error) {
	return
}

func (userdata *User) AcceptInvitation(senderUsername string, invitationPtr uuid.UUID, filename string) error {
	return nil
}

func (userdata *User) RevokeAccess(filename string, recipientUsername string) error {
	return nil
}
