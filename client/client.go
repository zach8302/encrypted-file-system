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
	PublicKeys map[string]([]byte)
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

type File struct {
	Next uuid.UUID
	Last uuid.UUID
	OwnerKey []byte
	SharedKey []byte
	UnlockKey []byte
	Filename, Contents, MAC, Owner []byte
	ID uuid.UUID
	//ShareTree string
}

type SharedFile struct {
	OwnerReceiver []byte
	SharedKey []byte
	//tree


}

type Invitation struct {
	OwnerReceiver []byte
	SharedKey []byte
	//tree
}

type FileSentinel struct {
	IsFile bool
	ID uuid.UUID
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

	unpackUserValues(&userdata, password)

	return &userdata, nil
}

func combineUserData(userdata *User) []byte {
	var combined string = ""
	names := [14]string  {"file", "filename", "fileMac", "fileKey", "treeKey", "treeMac", "fileLocKey", "RSAFile", "RSAMac", "RSAFilename", "RSAUsername", "RSATreeNode", "share", "userMAC"}

	for _, val := range names {
		salt := userdata.Salts[val]
		enc := userdata.EncKeys[val]
		combined += (string(salt) + string(enc))
	}

	combined += string(userdata.Salts["password"])

	return []byte(combined)

}
func generateUserSalts(userdata *User) {
	names := [15]string  {"file", "filename", "fileMac", "fileKey", "treeKey", "treeMac", "fileLocKey", "RSAFile", "RSAMac", "RSAFilename", "RSATreeNode", "RSAUsername", "userMAC", "share", "password"}
	set := make(map[string]bool)
	for _, val := range names {
		salt := userlib.RandomBytes(8)
		for set[val] == true {
			salt = userlib.RandomBytes(8)
		}
		set[string(salt[:])] = true
		userdata.Salts[val] = salt
	}

}

func generateUserKeys(userdata *User, password []byte) {
	names := [9]string  {"file", "filename", "fileMac", "fileKey", "treeKey", "treeMac", "fileLocKey", "share", "userMAC"}
	rsaNames := [5]string {"RSAFile", "RSAMac", "RSAUsername", "RSAFilename", "RSATreeNode"}
	keyLen := 16

	for _, val := range names {
		key := userlib.Argon2Key(password, userlib.RandomBytes(16), uint32(keyLen))
		salt := userdata.Salts[val]
		enc := userlib.Argon2Key(password, salt, uint32(keyLen))
		key = userlib.SymEnc(enc, userlib.RandomBytes(16), key)
		userdata.EncKeys[val] = key
	}
	//fix
	for _, val := range rsaNames {
		pub, priv, _ := userlib.PKEKeyGen()
		salt := userdata.Salts[val]
		enc := userlib.Argon2Key(password, salt, uint32(keyLen))
		serial, _ := json.Marshal(priv)
		key := userlib.SymEnc(enc, userlib.RandomBytes(16), serial)
		userdata.EncKeys[val] = key
		userlib.KeystoreSet(userdata.Username + val, pub)
	}
}


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
	names := [14]string  {"file", "filename", "fileMac", "fileKey", "treeKey", "treeMac", "fileLocKey", "RSAFile", "RSAMac", "RSAFilename", "RSATreeNode", "RSAUsername", "share", "userMAC"}
	for _, val := range names {
		salt := userdata.Salts[val]
		key := userlib.Argon2Key([]byte(password), salt, uint32(16))
		enc := userdata.EncKeys[val]
		store := userlib.SymDec(key, enc)
		userdata.Stored[val] = store
	}
}

func (userdata *User) StoreFile(filename string, content []byte) (err error) {
	var sentinel FileSentinel
	sentinel.IsFile = true
	
	var filedata File
	createFile(userdata, &filedata, filename, content)
	//generate uuid
	id := uuid.New()
	filedata.Last = id
	filedata.ID = id
	sentinel.ID = id

	serial, _ := json.Marshal(filedata)
	userlib.DatastoreSet(id, serial)

	loc := userdata.Username + "/" + filename
	locHash := userlib.Hash([]byte(loc))
	id, _ = uuid.FromBytes(locHash[:16])
	serial, _ = json.Marshal(sentinel)
	fmt.Println(userdata.Username)
	fmt.Println(filedata.OwnerKey)
	fmt.Println(filedata.ID)
	userlib.DatastoreSet(id, serial)
	
	//datastore
	return nil
}

func createFile(userdata *User, filedata *File, filename string, content []byte) {
	filedata.Next, _ = uuid.FromBytes([]byte("nil"))
	filedata.Last, _ = uuid.FromBytes([]byte("nil"))
	//generate the file keys
	generateFileKeys(userdata, filedata)
	//encrypt the contents and filename
	key := userdata.Stored["file"]
	fileKey := userlib.SymDec(key, filedata.OwnerKey)
	enc := userlib.SymEnc(fileKey, userlib.RandomBytes(16), content)
	filedata.Contents = enc

	nameKey := userlib.SymDec(key, filedata.OwnerKey)
	enc = userlib.SymEnc(nameKey, userlib.RandomBytes(16), ([]byte)(filename))
	filedata.Filename = enc
	//calculate the mac
	fileValues := unpackFileValues(filedata)
	macKey := userlib.SymDec(key, filedata.OwnerKey)
	filedata.MAC, _ = userlib.HMACEval(macKey, fileValues)
}

func generateFileKeys(userdata *User, filedata *File) {
	//choose a key and turn it to 6
	key := userdata.Stored["file"]
	reason := userlib.RandomBytes(16)
	derived, _ := userlib.HashKDF(key, reason)

	owner := derived[:16]
	filedata.OwnerKey = userlib.SymEnc(key, userlib.RandomBytes(16), owner)
	filedata.Owner = userlib.SymEnc(owner, userlib.RandomBytes(16), []byte(userdata.Username))


	reason = userlib.RandomBytes(16)
	derived, _ = userlib.HashKDF(key, reason)
	slice := derived[16:32]
	filedata.UnlockKey = userlib.SymEnc(key, userlib.RandomBytes(16), slice)
	filedata.SharedKey = userlib.SymEnc(slice, userlib.RandomBytes(16), owner)

}

func unpackFileValues(filedata *File) ([]byte) {
	data := ""
	names := [3]string {"contents", "mac", "filename"}
	for _, _ = range names {
		owner := filedata.OwnerKey
		//shared := filedata.SharedKeys
		data += string(owner) //+ string(shared) 
	}
	data += string(filedata.Filename) + string(filedata.Contents) + string(filedata.MAC)
	return []byte(data)
}

func (userdata *User) AppendToFile(filename string, content []byte) error {
	var sentinel FileSentinel
	loc := userdata.Username + "/" + filename
	locHash := userlib.Hash([]byte(loc))
	id, _ := uuid.FromBytes(locHash[:16])
	// if err != nil {
	// 	return nil, err
	// }
	dataJSON, ok := userlib.DatastoreGet(id)
	if !ok {
		//return nil, errors.New(strings.ToTitle("file not found"))
	}
	json.Unmarshal(dataJSON, &sentinel)

	if sentinel.IsFile {
		ownerAppend(userdata, filename, content, sentinel.ID)
	}


	return nil
}

func ownerAppend(userdata *User, filename string, content []byte, id uuid.UUID) error{
	dataJSON, ok := userlib.DatastoreGet(id)
	if !ok {
		//return nil, errors.New(strings.ToTitle("file not found"))
	}
	var filedata File
	json.Unmarshal(dataJSON, &filedata)

	lastID := filedata.Last
	dataJSON, ok = userlib.DatastoreGet(lastID)
	if !ok {
		return errors.New(strings.ToTitle("file not found"))
	}
	var lastFile File
	json.Unmarshal(dataJSON, &lastFile)

	//Create the file struct
	var appendFile File
	createFile(userdata, &appendFile, filename, content)
	//add to the end
	lastUUID := uuid.New()
	
	filedata.Last = lastUUID
	
	appendFile.ID = lastUUID
	serial, _ := json.Marshal(appendFile)
	userlib.DatastoreSet(lastUUID, serial)


	if lastFile.ID == filedata.ID {
		filedata.Next = lastUUID
	} else {
		lastFile.Next = lastUUID
		serial, _ = json.Marshal(lastFile)
		userlib.DatastoreSet(lastFile.ID, serial)
	}

	serial, _ = json.Marshal(filedata)
	userlib.DatastoreSet(filedata.ID, serial)

	return nil
}

func (userdata *User) LoadFile(filename string) (content []byte, err error) {
	var sentinel FileSentinel
	loc := userdata.Username + "/" + filename
	locHash := userlib.Hash([]byte(loc))
	id, _ := uuid.FromBytes(locHash[:16])
	dataJSON, ok := userlib.DatastoreGet(id)
	if !ok {
	// 	return nil, errors.New(strings.ToTitle("file not found"))
	}
	json.Unmarshal(dataJSON, &sentinel)
	// if err != nil {
	// 	return nil, err
	// }

	if sentinel.IsFile {
		id = sentinel.ID
		content = decryptFile(userdata, id)
	}

	

	
	return content, err
}

func getFile(filedata *File, id uuid.UUID) {
	dataJSON, ok := userlib.DatastoreGet(id)
	if !ok {
	// 	return nil, errors.New(strings.ToTitle("file not found"))
	}
	json.Unmarshal(dataJSON, &filedata)
}

//TODO errors
func decryptFile(userdata *User, file uuid.UUID) ([]byte) {
	var content string = ""
	var filedata File
	empty, _ := uuid.FromBytes([]byte("nil"))
	for file != empty {
		getFile(&filedata, file)
		key := userdata.Stored["file"]
		macKey := userlib.SymDec(key, filedata.OwnerKey)
		key = userdata.Stored["file"]
		fileKey := userlib.SymDec(key, filedata.OwnerKey)
		mac1 := filedata.MAC
		fileValues := unpackFileValues(&filedata)
		
		mac2, _ := userlib.HMACEval(macKey, fileValues)
		validMAC := userlib.HMACEqual(mac1, mac2)
		if !validMAC {
			//error
		}

		fmt.Println(userdata.Username)
		fmt.Println(filedata.OwnerKey)
		fmt.Println(filedata.ID)

		//decrypt the contents
		content += string(userlib.SymDec(fileKey, filedata.Contents))

		file = filedata.Next
	}
	return []byte(content)
}


func (userdata *User) CreateInvitation(filename string, recipientUsername string) (invitationPtr uuid.UUID, err error) {
	//todo integrity

	loc := userdata.Username + "/" + filename
	locHash := userlib.Hash([]byte(loc))
	id, _ := uuid.FromBytes(locHash[:16])
	data, ok := userlib.DatastoreGet(id)
	if !ok {
		//error
	}
	var sentinel FileSentinel
	json.Unmarshal(data, &sentinel)

	var filedata File
	getFile(&filedata, sentinel.ID)

	key := userdata.Stored["file"]
	fmt.Println(userdata.Username)
	fmt.Println(filedata.OwnerKey)
	fmt.Println(filedata.ID)
	shared := userlib.SymDec(key, filedata.OwnerKey)

	pub, ok := userlib.KeystoreGet(recipientUsername + "RSAFile")
	if !ok {
		//error
	}

	//deal with owner username for revoke

	var invitation Invitation
	invitation.SharedKey, _ = userlib.PKEEnc(pub, shared)

	serial, _ := json.Marshal(invitation)
	id = uuid.New()
	userlib.DatastoreSet(id, serial)

	return id, nil
}

func (userdata *User) AcceptInvitation(senderUsername string, invitationPtr uuid.UUID, filename string) error {
	return nil
}

func (userdata *User) RevokeAccess(filename string, recipientUsername string) error {
	return nil
}
