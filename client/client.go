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
	FileID uuid.UUID
}

type Invitation struct {
	OwnerReceiver []byte
	SharedKey []byte
	Filename string
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
	loc := userdata.Username + "/" + filename
	locHash := userlib.Hash([]byte(loc))
	sentinelID, _ := uuid.FromBytes(locHash[:16])
	data, ok := userlib.DatastoreGet(sentinelID)
	if ok {
		var sentinel FileSentinel
		json.Unmarshal(data, &sentinel)
		var key []byte
		var filedata File
		if sentinel.IsFile {
			key = userdata.Stored["file"]
			getFile(&filedata, sentinel.ID)
			updateFile(&filedata, filename, content, key)
			serial, _ := json.Marshal(filedata)
			userlib.DatastoreSet(sentinel.ID, serial)
		} else {
			var shared SharedFile
			getShared(&shared, sentinel.ID)
			key, _ = getSharedKey(userdata, &shared)
			getFile(&filedata, shared.FileID)	
			updateFile(&filedata, filename, content, key)
			serial, _ := json.Marshal(filedata)
			userlib.DatastoreSet(shared.FileID, serial)
		}
	} else {
		var sentinel FileSentinel
		sentinel.IsFile = true
		
		var filedata File
		createFile(userdata, &filedata, filename, content, false, nil, false, nil)
		//generate uuid
		id := uuid.New()
		filedata.Last = id
		filedata.ID = id
		sentinel.ID = id

		serial, _ := json.Marshal(filedata)
		userlib.DatastoreSet(id, serial)

		
		serial, _ = json.Marshal(sentinel)
		userlib.DatastoreSet(sentinelID, serial)
	}
	//datastore
	return nil
}

func copyKeys(to *File, from *File) {
	to.OwnerKey, to.SharedKey, to.UnlockKey = from.OwnerKey, from.SharedKey, from.UnlockKey
}

func createFile(userdata *User, filedata *File, filename string, content []byte, shared bool, pos []byte, append bool, prev *File) {
	filedata.Next, _ = uuid.FromBytes([]byte("nil"))
	filedata.Last, _ = uuid.FromBytes([]byte("nil"))
	//generate the file keys
	if append {
		copyKeys(filedata, prev)
	} else {
		generateFileKeys(userdata, filedata)	
	}
	//encrypt the contents and filename
	var key []byte
	if shared {
		key = pos
		fmt.Println("HI")
		fmt.Println(pos)
	} else {
		key = userlib.SymDec(userdata.Stored["file"], filedata.OwnerKey)
		fmt.Println("BYE")
		fmt.Println(filedata.OwnerKey)
	}
	
	enc := userlib.SymEnc(key, userlib.RandomBytes(16), content)
	filedata.Contents = enc

	enc = userlib.SymEnc(key, userlib.RandomBytes(16), ([]byte)(filename))
	filedata.Filename = enc
	//calculate the mac
	fileValues := unpackFileValues(filedata)
	filedata.MAC, _ = userlib.HMACEval(key, fileValues)
}

func updateFile(filedata *File, filename string, content []byte, key []byte) {
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
		fmt.Println("1")
		fmt.Println(sentinel.ID)
		ownerAppend(userdata, filename, content, sentinel.ID, false, nil)
	} else {
		var shared SharedFile
		getShared(&shared, sentinel.ID)
		fmt.Println("3")
		fmt.Println(shared.FileID)
		key, _ := getSharedKey(userdata, &shared)
		ownerAppend(userdata, filename, content, shared.FileID, true, key)
	}


	return nil
}

func ownerAppend(userdata *User, filename string, content []byte, id uuid.UUID, shared bool, pos []byte) error{
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
	if !shared {
		createFile(userdata, &appendFile, filename, content, false, nil, true, &lastFile)
	} else {
		createFile(userdata, &appendFile, filename, content, true, pos, true, &lastFile)
	}
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
		content = decryptFile(userdata, id, false, nil)
	} else {
		var shared SharedFile
		getShared(&shared, sentinel.ID)
		key, _ := getSharedKey(userdata, &shared)
		content = decryptFile(userdata, shared.FileID, true, key)
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

func getShared(filedata *SharedFile, id uuid.UUID) {
	dataJSON, ok := userlib.DatastoreGet(id)
	if !ok {
	// 	return nil, errors.New(strings.ToTitle("file not found"))
	}
	json.Unmarshal(dataJSON, &filedata)
}

func getSharedKey(userdata *User, filedata *SharedFile) ([]byte, error) {
	enc := filedata.SharedKey
	serial := userdata.Stored["RSAFile"]
	var priv userlib.PKEDecKey
	json.Unmarshal(serial, &priv)
	return userlib.PKEDec(priv, enc)
}

//TODO errors
func decryptFile(userdata *User, file uuid.UUID, shared bool, pos []byte) ([]byte) {
	var content string = ""
	var filedata File
	empty, _ := uuid.FromBytes([]byte("nil"))
	for file != empty {
		getFile(&filedata, file)
		var key []byte
		if shared {
			key = pos
		} else {
			key = userlib.SymDec(userdata.Stored["file"], filedata.OwnerKey)
		}
		mac1 := filedata.MAC
		fileValues := unpackFileValues(&filedata)
		
		mac2, _ := userlib.HMACEval(key, fileValues)
		validMAC := userlib.HMACEqual(mac1, mac2)
		if !validMAC {
			//error
		}
		//decrypt the contents
		content += string(userlib.SymDec(key, filedata.Contents))

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

	if sentinel.IsFile {
		var filedata File
		getFile(&filedata, sentinel.ID)
		key := userdata.Stored["file"]
		shared := userlib.SymDec(key, filedata.OwnerKey)
		fmt.Println("YO")
		fmt.Println(filedata.OwnerKey)
		name := userlib.SymDec(shared, filedata.Filename)

		pub, ok := userlib.KeystoreGet(recipientUsername + "RSAFile")
		if !ok {
			//error
		}

		//deal with owner username for revoke

		var invitation Invitation
		invitation.SharedKey, _ = userlib.PKEEnc(pub, shared)
		invitation.Filename = string(name)

		serial, _ := json.Marshal(invitation)
		id = uuid.New()
		userlib.DatastoreSet(id, serial)
		return id, nil
	} else {
		var shared SharedFile
		getShared(&shared, sentinel.ID)
		var filedata File
		getFile(&filedata, sentinel.ID)
		key, _ := getSharedKey(userdata, &shared)
		name := userlib.SymDec(key, filedata.Filename)
		//getFile(&filedata, shared.FileID)
		pub, ok := userlib.KeystoreGet(recipientUsername + "RSAFile")
		if !ok {
			//error

		}

		//deal with owner username for revoke
		fmt.Println("YO")
		fmt.Println(key)
		var invitation Invitation
		invitation.SharedKey, _ = userlib.PKEEnc(pub, key)
		invitation.Filename = string(name)


		serial, _ := json.Marshal(invitation)
		id = uuid.New()
		userlib.DatastoreSet(id, serial)
		return id, nil
	}
	
}

func (userdata *User) AcceptInvitation(senderUsername string, invitationPtr uuid.UUID, filename string) error {
	var invite Invitation
	var shared SharedFile
	var sentinel FileSentinel
	dataJSON, ok := userlib.DatastoreGet(invitationPtr)
	if !ok {
	// 	return nil, errors.New(strings.ToTitle("file not found"))
	}
	json.Unmarshal(dataJSON, &invite)
	

	shared.OwnerReceiver, shared.SharedKey = invite.OwnerReceiver, invite.SharedKey
	loc := senderUsername + "/" + invite.Filename
	locHash := userlib.Hash([]byte(loc))
	fileLoc, _ := uuid.FromBytes(locHash[:16])
	var oldSentinel FileSentinel
	dataJSON, ok = userlib.DatastoreGet(fileLoc)
	if !ok {
	// 	return nil, errors.New(strings.ToTitle("file not found"))
	}
	json.Unmarshal(dataJSON, &oldSentinel)


	shared.FileID = oldSentinel.ID
	fmt.Println("2")
	fmt.Println(shared.FileID)
	id := uuid.New()
	serial, _ := json.Marshal(shared)
	userlib.DatastoreSet(id, serial)

	sentinel.IsFile = false
	sentinel.ID = id
	loc = userdata.Username + "/" + filename
	locHash = userlib.Hash([]byte(loc))
	sentinelID, _ := uuid.FromBytes(locHash[:16])
	serial, _ = json.Marshal(sentinel)
	userlib.DatastoreSet(sentinelID, serial)

	return nil
}

func (userdata *User) RevokeAccess(filename string, recipientUsername string) error {
	return nil
}
