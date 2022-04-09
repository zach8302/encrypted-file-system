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
	//"fmt"

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
	Username string
	Filename string
	Children []uuid.UUID
	Accepted bool
	Invite uuid.UUID
	Shared uuid.UUID
}

type File struct {
	Next uuid.UUID
	Last uuid.UUID
	OwnerKey []byte
	MacKey []byte
	NameKey []byte
	FileKey []byte
	Filename, Contents, MAC, Owner []byte
	ID uuid.UUID
	TreeID uuid.UUID
}

type SharedFile struct {
	Username string
	SharedKey []byte
	TreeID uuid.UUID
	FileID uuid.UUID
}

type Invitation struct {
	OwnerReceiver []byte
	SharedKey []byte
	MacKey []byte
	Filename []byte
	Signature []byte
	Mac []byte
	TreeID uuid.UUID
}

type FileSentinel struct {
	IsFile bool
	ID uuid.UUID

}

// NOTE: The following methods have toy (insecure!) implementations.

func InitUser(username string, password string) (userdataptr *User, err error) {
	//create a user struct
	nameHash := userlib.Hash([]byte(username))
	id, err := uuid.FromBytes(nameHash[:16])
	if err != nil {
		return nil, errors.New(strings.ToTitle("Internal Error"))
	}
	_, ok := userlib.DatastoreGet(id)

	if ok {
		return nil, errors.New(strings.ToTitle("User Already Exists"))
	}
	
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
	if enc == nil {
		return nil, errors.New(strings.ToTitle("decryption failure"))
	}
	macKey := userlib.SymDec(key, enc)
	combined := combineUserData(&userdata)
	userdata.UserMAC, err = userlib.HMACEval(macKey, combined)
	if err != nil {
		return nil, errors.New(strings.ToTitle("Internal Error"))
	}
	userdata.PasswordHash = userlib.Hash([]byte(password + string(userdata.Salts["password"])))

	serial, err := json.Marshal(userdata)
	if err != nil {
		return nil, errors.New(strings.ToTitle("Internal Error"))
	}
	userlib.DatastoreSet(id, serial)
	
	unpackUserValues(&userdata, password)

	return &userdata, nil
}

func combineUserData(userdata *User) []byte {
	var combined string = ""
	names := [11]string  {"file", "fileMac", "treeKey", "RSAInviteMac", "RSAFile", "RSAMac", "RSAFilename", "RSATreeNode", "userMAC", "share", "DSA"}
	for _, val := range names {
		salt := userdata.Salts[val]
		enc := userdata.EncKeys[val]
		combined += (string(salt) + string(enc))
	}

	combined += string(userdata.Salts["password"])

	return []byte(combined)

}
func generateUserSalts(userdata *User) {
	names := [12]string  {"file", "fileMac", "treeKey", "RSAInviteMac", "RSAFile", "RSAMac", "RSAFilename", "RSATreeNode", "userMAC", "share", "password", "DSA"}
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

func generateUserKeys(userdata *User, password []byte) (error){
	names := [6]string  {"file", "fileMac", "treeKey", "share", "userMAC"}
	rsaNames := [5]string {"RSAFile", "RSAMac", "RSAFilename", "RSATreeNode", "RSAInviteMac"}

	keyLen := 16

	for _, val := range names {
		key := userlib.Argon2Key(password, userlib.RandomBytes(16), uint32(keyLen))
		salt := userdata.Salts[val]
		enc := userlib.Argon2Key(password, salt, uint32(keyLen))
		key = userlib.SymEnc(enc, userlib.RandomBytes(16), key)
		userdata.EncKeys[val] = key
	}
	for _, val := range rsaNames {
		pub, priv, err := userlib.PKEKeyGen()
		if err != nil {
			return errors.New(strings.ToTitle("Internal Error"))
		}
		salt := userdata.Salts[val]
		enc := userlib.Argon2Key(password, salt, uint32(keyLen))
		serial, err := json.Marshal(priv)
		if err != nil {
			return errors.New(strings.ToTitle("Internal Error"))
		}
		key := userlib.SymEnc(enc, userlib.RandomBytes(16), serial)
		userdata.EncKeys[val] = key
		userlib.KeystoreSet(userdata.Username + "/" + val, pub)
	}
	priv, pub, err := userlib.DSKeyGen()
	if err != nil {
		return errors.New(strings.ToTitle("Internal Error"))
	}
	salt := userdata.Salts["DSA"]
	enc := userlib.Argon2Key(password, salt, uint32(keyLen))
	serial, err := json.Marshal(priv)
	if err != nil {
		return errors.New(strings.ToTitle("Internal Error"))
	}
	key := userlib.SymEnc(enc, userlib.RandomBytes(16), serial)
	userdata.EncKeys["DSA"] = key
	userlib.KeystoreSet(userdata.Username + "/" + "DSA", pub)

	return nil

}


func GetUser(username string, password string) (userdataptr *User, err error) {
	//TODO MAKE SURE IT EXIST
	var userdata User
	nameHash := userlib.Hash([]byte(username))
	id, err := uuid.FromBytes(nameHash[:16])
	if err != nil {
		return nil, errors.New(strings.ToTitle("Internal Error"))
	}
	data, ok := userlib.DatastoreGet(id)
	if !ok {
		return nil, errors.New(strings.ToTitle("User not found"))
	}
	json.Unmarshal(data, &userdata)

	mac1 := userdata.UserMAC
	salt := userdata.Salts["userMAC"]
	key := userlib.Argon2Key([]byte(password), salt, uint32(16))
	enc := userdata.EncKeys["userMAC"]
	if enc == nil {
		return nil, errors.New(strings.ToTitle("decryption failure"))
	}
	macKey := userlib.SymDec(key, enc)
	combined := combineUserData(&userdata)
	mac2, err := userlib.HMACEval(macKey, combined)
	if err != nil {
		return nil, errors.New(strings.ToTitle("Internal Error"))
	}
	validMAC := userlib.HMACEqual(mac1, mac2)
	if !validMAC {
		return nil, errors.New(strings.ToTitle("Data Integrity Error"))
	}

	//Password check
	passHash := userlib.Hash([]byte(password + string(userdata.Salts["password"])))
	hashOk := userlib.HMACEqual(passHash, userdata.PasswordHash)
	if !hashOk {
		return nil, errors.New(strings.ToTitle("Invalid Password"))
	}

	//Unpack values
	unpackUserValues(&userdata, password)
	//return
	return &userdata, nil
}

func unpackUserValues(userdata *User, password string) {
	names := [11]string  {"file", "fileMac", "treeKey", "RSAInviteMac", "RSAFile", "RSAMac", "RSAFilename", "RSATreeNode", "userMAC", "share", "DSA"}
	for _, val := range names {
		salt := userdata.Salts[val]
		key := userlib.Argon2Key([]byte(password), salt, uint32(16))
		enc := userdata.EncKeys[val]
		if enc == nil {
			//error
		}
		store := userlib.SymDec(key, enc)
		userdata.Stored[val] = store
	}
}

func (userdata *User) StoreFile(filename string, content []byte) (err error) {
	loc := userdata.Username + "/" + filename
	locHash := userlib.Hash([]byte(loc))
	sentinelID, err := uuid.FromBytes(locHash[:16])
	if err != nil {
		return errors.New(strings.ToTitle("Internal Error"))
	}
	data, ok := userlib.DatastoreGet(sentinelID)
	if ok {
		var sentinel FileSentinel
		json.Unmarshal(data, &sentinel)
		var key []byte
		var filedata File
		if sentinel.IsFile {
			key = userdata.Stored["file"]
			getFile(&filedata, sentinel.ID)
			updateFile(userdata, &filedata, filename, content, key, false, nil)
			serial, err := json.Marshal(filedata)
			if err != nil {
				return errors.New(strings.ToTitle("Internal Error"))
			}
			userlib.DatastoreSet(sentinel.ID, serial)
		} else {
			var shared SharedFile
			getShared(&shared, sentinel.ID)
			key, err = getSharedKey(userdata, &shared)
			if err != nil {
				return errors.New(strings.ToTitle("Internal Error"))
			}
			if !authenticateFile(userdata, &shared) {
				return errors.New(strings.ToTitle("Not allowed to access"))
			}
			getFile(&filedata, shared.FileID)	
			updateFile(userdata, &filedata, filename, content, key, true, shared.SharedKey)
			serial, err := json.Marshal(filedata)
			if err != nil {
				return errors.New(strings.ToTitle("Internal Error"))
			}
			userlib.DatastoreSet(shared.FileID, serial)
		}
	} else {
		var sentinel FileSentinel
		sentinel.IsFile = true
		
		var filedata File
		id := uuid.New()

		
		createFile(userdata, &filedata, filename, content, false, nil, false, nil)
		//generate uuid
		filedata.Last = id
		filedata.ID = id
		sentinel.ID = id
		

		serial, err := json.Marshal(filedata)
		if err != nil {
			return errors.New(strings.ToTitle("Internal Error"))
		}
		userlib.DatastoreSet(id, serial)

		
		serial, err = json.Marshal(sentinel)
		if err != nil {
				return errors.New(strings.ToTitle("Internal Error"))
		}


		userlib.DatastoreSet(sentinelID, serial)
	}
	//datastore
	return nil
}

func copyKeys(to *File, from *File) {
	to.OwnerKey, to.MacKey, to.FileKey, to.NameKey = from.OwnerKey, from.MacKey, from.FileKey, from.NameKey
}

func createFile(userdata *User, filedata *File, filename string, content []byte, shared bool, pos []byte, append bool, prev *File) (error) {
	filedata.Next, _ = uuid.FromBytes([]byte("nil"))
	filedata.Last, _ = uuid.FromBytes([]byte("nil"))
	//generate the file keys
	if append {
		copyKeys(filedata, prev)
	} else {
		generateFileKeys(userdata, filedata)
		var tree TreeNode
		tree.Username = userdata.Username
		serial, err := json.Marshal(tree)
		if err != nil {
			return errors.New(strings.ToTitle("Internal Error"))
		}
		id := uuid.New()
		userlib.DatastoreSet(id, serial)
		filedata.TreeID	= id
		userlib.DatastoreSet(id, serial)
	}
	//encrypt the contents and filename
	var key []byte
	if shared {
		key = pos
	} else {
		if filedata.OwnerKey == nil {
			return errors.New(strings.ToTitle("decryption failure"))
		}
		key = userlib.SymDec(userdata.Stored["file"], filedata.OwnerKey)
	}
	fileKey, name, mac := getFileKeys(filedata, key)
	validateFile(mac, filedata.Filename, filedata.Contents, filedata.MAC)
	
	enc := userlib.SymEnc(fileKey, userlib.RandomBytes(16), content)
	filedata.Contents = enc

	enc = userlib.SymEnc(name, userlib.RandomBytes(16), ([]byte)(filename))
	filedata.Filename = enc
	//calculate the mac
	fileValues := string(filedata.Filename) + string(filedata.Contents)
	filedata.MAC, _ = userlib.HMACEval(mac, []byte(fileValues))

	return nil
}

func updateFile(userdata *User, filedata *File, filename string, content []byte, key []byte, shared bool, pos []byte) {
	var owner []byte
	if !shared{
		owner = userlib.SymDec(key, filedata.OwnerKey)
	} else {
		owner = key
	}
	fileKey, nameKey, macKey := getFileKeys(filedata, owner)

	enc := userlib.SymEnc(fileKey, userlib.RandomBytes(16), content)
	filedata.Contents = enc


	enc = userlib.SymEnc(nameKey, userlib.RandomBytes(16), ([]byte)(filename))
	filedata.Filename = enc
	//calculate the mac
	fileValues := string(filedata.Filename) + string(filedata.Contents)
	
	filedata.MAC, _ = userlib.HMACEval(macKey, []byte(fileValues))
	filedata.Next, _ = uuid.FromBytes([]byte("nil"))

}

func generateFileKeys(userdata *User, filedata *File) {
	//choose a key and turn it to 6
	key := userdata.Stored["file"]
	reason := userlib.RandomBytes(16)
	derived, _ := userlib.HashKDF(key, reason)

	owner := derived[:16]
	filedata.OwnerKey = userlib.SymEnc(key, userlib.RandomBytes(16), owner)
	filedata.Owner = userlib.SymEnc(owner, userlib.RandomBytes(16), []byte(userdata.Username))

	slice := derived[16:32]
	filedata.MacKey = userlib.SymEnc(owner, userlib.RandomBytes(16), slice)

	name := derived[32:48]
	filedata.NameKey = userlib.SymEnc(owner, userlib.RandomBytes(16), name)

	content := derived[48:]
	filedata.FileKey = userlib.SymEnc(owner, userlib.RandomBytes(16), content)

}


func (userdata *User) AppendToFile(filename string, content []byte) error {
	var sentinel FileSentinel
	loc := userdata.Username + "/" + filename
	locHash := userlib.Hash([]byte(loc))
	id, err := uuid.FromBytes(locHash[:16])
	if err != nil {
		return err
	}
	dataJSON, ok := userlib.DatastoreGet(id)
	if !ok {
		return errors.New(strings.ToTitle("file not found"))
	}
	json.Unmarshal(dataJSON, &sentinel)



	if sentinel.IsFile {
		err := ownerAppend(userdata, filename, content, sentinel.ID, false, nil)
		if err != nil {
			return errors.New(strings.ToTitle("Internal Error: File error"))
		}
	} else {
		var shared SharedFile
		getShared(&shared, sentinel.ID)
		if !authenticateFile(userdata, &shared) {
				return errors.New(strings.ToTitle("Not allowed to access"))
			}
		key, _ := getSharedKey(userdata, &shared)
		err := ownerAppend(userdata, filename, content, shared.FileID, true, key)
		if err != nil {
			return errors.New(strings.ToTitle("Internal Error: Shared error"))
		}
	}



	return nil
}

func getFileKeys(filedata *File, key []byte) ([]byte, []byte, []byte) {
	file := userlib.SymDec(key, filedata.FileKey)
	name := userlib.SymDec(key, filedata.NameKey)
	mac := userlib.SymDec(key, filedata.MacKey)

	return file, name, mac
}

func ownerAppend(userdata *User, filename string, content []byte, id uuid.UUID, shared bool, pos []byte) error{
	dataJSON, ok := userlib.DatastoreGet(id)

	if !ok {
		return errors.New(strings.ToTitle("file not found"))
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
	var shared SharedFile
	if sentinel.IsFile {
		id = sentinel.ID
		content, err = decryptFile(userdata, filename, id, false, nil)
		if err != nil {
			return nil, errors.New(strings.ToTitle("Internal Error 2"))
		}
		

	} else {
		getShared(&shared, sentinel.ID)
		id = shared.FileID
		if !authenticateFile(userdata, &shared) {
			return nil, errors.New(strings.ToTitle("Not allowed to access"))
		}
		key, _ := getSharedKey(userdata, &shared)
		content, err = decryptFile(userdata, filename, shared.FileID, true, key)
		if err != nil {
			return nil, errors.New(strings.ToTitle("Internal Error 1"))
		}
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

func validateFile(key []byte, filename []byte, content []byte, mac []byte) (bool) {
	fileValues := string(filename) + string(content)
	new, _ := userlib.HMACEval(key, []byte(fileValues))
	return userlib.HMACEqual(mac, new)
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
func decryptFile(userdata *User, filename string, file uuid.UUID, shared bool, pos []byte) ([]byte, error) {
	var content string = ""
	var filedata File
	empty, _ := uuid.FromBytes([]byte("nil"))
	for file != empty {
		getFile(&filedata, file)
		var key []byte
		if shared {
			key = pos
		} else {
			if filedata.OwnerKey == nil {
				return nil, errors.New(strings.ToTitle("decryption failure"))
			}
			key = userlib.SymDec(userdata.Stored["file"], filedata.OwnerKey)
		}
		fileKey, _, mac := getFileKeys(&filedata, key)
		validateFile(mac, filedata.Filename, filedata.Contents, filedata.MAC)
		//decrypt the contents
		content += string(userlib.SymDec(fileKey, filedata.Contents))

		file = filedata.Next
	}
	return []byte(content), nil
}


func (userdata *User) CreateInvitation(filename string, recipientUsername string) (invitationPtr uuid.UUID, err error) {
	//todo integrity
	invId := uuid.New()
	loc := userdata.Username + "/" + filename
	locHash := userlib.Hash([]byte(loc))
	id, _ := uuid.FromBytes(locHash[:16])
	data, ok := userlib.DatastoreGet(id)
	if !ok {
		return uuid.New(), errors.New(strings.ToTitle("Internal Error"))
	}
	var sentinel FileSentinel
	json.Unmarshal(data, &sentinel)
	macPub, ok := userlib.KeystoreGet(recipientUsername + "/" + "RSAInviteMac")
	if !ok {
		return uuid.New(), errors.New(strings.ToTitle("Internal Error"))
	}
	key := userdata.Stored["userMAC"]
	reason := userlib.RandomBytes(16)
	derived, _ := userlib.HashKDF(key, reason)
	derived = derived[:16]


	if sentinel.IsFile {
		var filedata File
		getFile(&filedata, sentinel.ID)
		key := userdata.Stored["file"]
		shared := userlib.SymDec(key, filedata.OwnerKey)

		var tree TreeNode
		treeFromFile(&filedata, &tree)

		var newTree TreeNode
		treeId := uuid.New()

		children := tree.Children[:]
		x := append(children, treeId)

		tree.Children = x
		newTree.Username = recipientUsername
		newTree.Invite = invId


		serial, _ := json.Marshal(tree)
		userlib.DatastoreSet(filedata.TreeID, serial)

		serial, _ = json.Marshal(newTree)
		userlib.DatastoreSet(treeId, serial)

		pub, ok := userlib.KeystoreGet(recipientUsername + "/" + "RSAFile")
		if !ok {
			return uuid.New(), errors.New(strings.ToTitle("Internal Error"))
		}

		name, ok := userlib.KeystoreGet(recipientUsername + "/" + "RSAFilename")
		if !ok {
			return uuid.New(), errors.New(strings.ToTitle("Internal Error"))
		}

		//deal with owner username for revoke

		var invitation Invitation
		invitation.SharedKey, _ = userlib.PKEEnc(pub, shared)
		invitation.Filename, _ = userlib.PKEEnc(name, []byte(filename))

		invitation.MacKey, _ = userlib.PKEEnc(macPub, derived)
		invData := string(invitation.SharedKey) + string(invitation.Filename) + string(invitation.MacKey)
		invitation.Mac, err = userlib.HMACEval(derived, []byte(invData))
		if err != nil {
			return uuid.New(), errors.New(strings.ToTitle("Internal Error"))
		}

		invitation.TreeID = treeId
		encSig := userdata.Stored["DSA"]
		var sig userlib.DSSignKey
		json.Unmarshal(encSig, &sig)
		verify, err := userlib.DSSign(sig, []byte(filename))
		if err != nil {
			return uuid.New(), errors.New(strings.ToTitle("Signature error"))
		}
		invitation.Signature = verify



		serial, _ = json.Marshal(invitation)
		id = invId
		userlib.DatastoreSet(id, serial)
		return id, nil
	} else {
		var shared SharedFile
		getShared(&shared, sentinel.ID)
		var filedata File
		getFile(&filedata, shared.FileID)
		key, _ := getSharedKey(userdata, &shared)
		//getFile(&filedata, shared.FileID)
		pub, ok := userlib.KeystoreGet(recipientUsername + "/" + "RSAFile")
		if !ok {
			return uuid.New(), errors.New(strings.ToTitle("Internal Error"))
		}

		//deal with owner username for revoke
		var tree TreeNode
		treeFromShared(&shared, &tree)

		var newTree TreeNode
		treeId := uuid.New()

		children := tree.Children[:]
		x := append(children, treeId)

		tree.Children = x
		newTree.Username = recipientUsername

		serial, _ := json.Marshal(newTree)
		userlib.DatastoreSet(treeId, serial)

		name, ok := userlib.KeystoreGet(recipientUsername + "/" + "RSAFilename")
		if !ok {
			return uuid.New(), errors.New(strings.ToTitle("Internal Error"))
		}

		var invitation Invitation
		invitation.SharedKey, _ = userlib.PKEEnc(pub, key)
		invitation.Filename, _ = userlib.PKEEnc(name, []byte(filename))
		invitation.MacKey, _ = userlib.PKEEnc(macPub, derived)
		invData := string(invitation.SharedKey) + string(invitation.Filename) + string(invitation.MacKey)
		invitation.Mac, err = userlib.HMACEval(derived, []byte(invData))
		if err != nil {
			return uuid.New(), errors.New(strings.ToTitle("Internal Error"))
		}
		invitation.TreeID = treeId
		encSig := userdata.Stored["DSA"]
		var sig userlib.DSSignKey
		json.Unmarshal(encSig, &sig)
		verify, err := userlib.DSSign(sig, []byte(filename))
		if err != nil {
			return uuid.New(), errors.New(strings.ToTitle("Signature error"))
		}
		invitation.Signature = verify
		
		id = invId
		tree.Invite = id
		serial, _ = json.Marshal(tree)
		userlib.DatastoreSet(shared.TreeID, serial)
		serial, _ = json.Marshal(invitation)
		userlib.DatastoreSet(id, serial)

		return id, nil
	}
	
}

func treeFromFile(filedata *File, tree *TreeNode) (error) {
	id := filedata.TreeID
	data, ok := userlib.DatastoreGet(id)
	if !ok {
		return errors.New(strings.ToTitle("Internal Error"))
	}
	json.Unmarshal(data, tree)
	return nil
}

func treeFromShared(shared *SharedFile, tree *TreeNode) (error) {
	id := shared.TreeID
	data, ok := userlib.DatastoreGet(id)
	if !ok {
		return errors.New(strings.ToTitle("Internal Error"))
	}
	json.Unmarshal(data, tree)
	return nil
}

func (userdata *User) AcceptInvitation(senderUsername string, invitationPtr uuid.UUID, filename string) error {
	var invite Invitation
	var shared SharedFile
	var sentinel FileSentinel
	dataJSON, ok := userlib.DatastoreGet(invitationPtr)
	if !ok {
		return errors.New(strings.ToTitle("file not found"))
	}
	json.Unmarshal(dataJSON, &invite)

	enc := invite.MacKey
	serial := userdata.Stored["RSAInviteMac"]
	var priv userlib.PKEDecKey
	json.Unmarshal(serial, &priv)
	macKey, _ := userlib.PKEDec(priv, enc)
	invData := string(invite.SharedKey) + string(invite.Filename) + string(invite.MacKey)
	mac, err := userlib.HMACEval(macKey, []byte(invData))
	validMAC := userlib.HMACEqual(mac, invite.Mac)
	if !validMAC {
		return errors.New(strings.ToTitle("Data Integrity Error"))
	}


	shared.SharedKey = invite.SharedKey
	shared.Username = userdata.Username
	shared.TreeID = invite.TreeID
	serial = userdata.Stored["RSAFilename"]
	json.Unmarshal(serial, &priv)
	name, err := userlib.PKEDec(priv, invite.Filename)
	if err != nil {
		return errors.New(strings.ToTitle("Decryption Error"))
	}

	vk, ok := userlib.KeystoreGet(senderUsername + "/" + "DSA")
	if !ok {
		return errors.New(strings.ToTitle("Internal Error"))
	}


	err = userlib.DSVerify(vk, []byte(name), invite.Signature)
	if err != nil {
		return errors.New(strings.ToTitle("Cannot verify sender"))
	}


	loc := senderUsername + "/" + string(name)
	locHash := userlib.Hash([]byte(loc))
	fileLoc, _ := uuid.FromBytes(locHash[:16])
	var oldSentinel FileSentinel
	dataJSON, ok = userlib.DatastoreGet(fileLoc)
	if !ok {
		return errors.New(strings.ToTitle("file not found"))
	}
	json.Unmarshal(dataJSON, &oldSentinel)

	if oldSentinel.IsFile {
		shared.FileID = oldSentinel.ID
	} else {
		var oldShared SharedFile
		getShared(&oldShared, oldSentinel.ID)
		shared.FileID = oldShared.FileID
	}

	id := uuid.New()
	serial, _ = json.Marshal(shared)
	userlib.DatastoreSet(id, serial)


	var node TreeNode
	data, ok := userlib.DatastoreGet(invite.TreeID)
	if !ok {
		return errors.New(strings.ToTitle("Internal Error"))
	}
	json.Unmarshal(data, &node)

	node.Shared = id
	node.Accepted = true

	serial, _ = json.Marshal(node)
	userlib.DatastoreSet(invite.TreeID, serial)

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
	loc := userdata.Username + "/" + filename
	locHash := userlib.Hash([]byte(loc))
	id, _ := uuid.FromBytes(locHash[:16])
	var filedata File 
	var sentinel FileSentinel
	dataJSON, ok := userlib.DatastoreGet(id)
	if !ok {
		return errors.New(strings.ToTitle("file not found"))
	}
	json.Unmarshal(dataJSON, &sentinel)
	getFile(&filedata, sentinel.ID)
	ok, x := findUser(filedata.TreeID, recipientUsername)
	if ok != true {
		return errors.New(strings.ToTitle("user not found"))
	}
	pruneTree(x)

	reencryptFile(userdata, filename, filedata.TreeID)
	err := reshareFile(userdata, filename, filedata.TreeID)
	if err != nil {
		return errors.New(strings.ToTitle("ReshareError"))
	}


	return nil
}

func findUser(tree uuid.UUID, username string) (bool, uuid.UUID) {

	i := 0
	q := make([]uuid.UUID, 1)
	q[0] = tree
	var node TreeNode
	for i < len(q) {
		id := q[i]
		data, ok := userlib.DatastoreGet(id)
		if !ok {
			i+=1
			continue
		}
		json.Unmarshal(data, &node)

		if node.Username == username {
			return true, id
		}
		
		for _, child := range node.Children {
			q = append(q, child)
		}
		i += 1

	}
	return false, uuid.New()
	//error

}


func pruneTree(tree uuid.UUID) (error) {
	i := 0
	q := make([]uuid.UUID, 1)
	q[0] = tree
	var node TreeNode
	for i < len(q) {
		id := q[i]
		data, ok := userlib.DatastoreGet(id)
		if !ok {
			i += 1
			continue
		}
		json.Unmarshal(data, &node)
		for _, child := range node.Children {
			q = append(q, child)


		}

		userlib.DatastoreDelete(id)
		i += 1
	}
	return nil
	
}

func reencryptFile(userdata *User, filename string, tree uuid.UUID) {
	content, err := userdata.LoadFile(filename)
	if err != nil {
		//err
	}
	loc := userdata.Username + "/" + filename
	locHash := userlib.Hash([]byte(loc))
	fileLoc, _ := uuid.FromBytes(locHash[:16])
	userlib.DatastoreDelete(fileLoc)

	userdata.StoreFile(filename, content)



	


}

func reshareFile(userdata *User, filename string, tree uuid.UUID) (error) {
	i := 0
	q := make([]uuid.UUID, 1)
	q[0] = tree
	var sentinel FileSentinel
	loc := userdata.Username + "/" + filename
	locHash := userlib.Hash([]byte(loc))
	fileLoc, _ := uuid.FromBytes(locHash[:16])
	dataJSON, ok := userlib.DatastoreGet(fileLoc)
	if !ok {
		return errors.New(strings.ToTitle("file not found"))
	}
	json.Unmarshal(dataJSON, &sentinel)
	var filedata File
	getFile(&filedata, sentinel.ID)

	key := userlib.SymDec(userdata.Stored["file"], filedata.OwnerKey)

	var node TreeNode
	for i < len(q) {
		id := q[i]
		data, ok := userlib.DatastoreGet(id)
		if !ok{
			i += 1
			continue
			
		}
		json.Unmarshal(data, &node)
		for _, child := range node.Children {
			q = append(q, child)

		}
		if i ==0 {
			i +=1
			continue
		}

		pub, ok := userlib.KeystoreGet(node.Username + "/" + "RSAFile")
		encKey, _ := userlib.PKEEnc(pub, key)
		if !ok {
			return errors.New(strings.ToTitle("Internal Error"))
		}

		if !node.Accepted {
			updateInvite(userdata, id, encKey, sentinel.ID)
		} else {
			updateSharedFile(userdata, id, encKey, sentinel.ID)
		}
		i += 1
	}

	return nil

}

func updateSharedFile(userdata *User, tree uuid.UUID, key []byte, loc uuid.UUID) (error) {
	var node TreeNode
	data, ok := userlib.DatastoreGet(tree)
	if !ok {
		return errors.New(strings.ToTitle("Internal Error"))
	}
	json.Unmarshal(data, &node)
	var shared SharedFile
	getShared(&shared, node.Shared)
	shared.SharedKey = key
	shared.FileID = loc

	serial, _ := json.Marshal(shared)
	userlib.DatastoreSet(node.Shared, serial)

	return nil

}

func updateInvite(userdata *User, tree uuid.UUID, key []byte, loc uuid.UUID) (error){
	mac := userdata.Stored["userMAC"]
	reason := userlib.RandomBytes(16)
	derived, _ := userlib.HashKDF(mac, reason)
	derived = derived[:16]
	var node TreeNode
	data, ok := userlib.DatastoreGet(tree)
	if !ok {
		return errors.New(strings.ToTitle("Internal Error"))
	}
	json.Unmarshal(data, &node)
	var invite Invitation
	data, ok = userlib.DatastoreGet(node.Invite)
	if !ok {
		return errors.New(strings.ToTitle("Internal Error"))
	}
	json.Unmarshal(data, &invite)
	invite.SharedKey = key

	macPub, ok := userlib.KeystoreGet(node.Username + "/" + "RSAInviteMac")
	if !ok {
		return errors.New(strings.ToTitle("Internal Error"))
	}

	invite.MacKey, _ = userlib.PKEEnc(macPub, derived)
	invData := string(invite.SharedKey) + string(invite.Filename) + string(invite.MacKey)
	invite.Mac, _ = userlib.HMACEval(derived, []byte(invData))


	serial, _ := json.Marshal(invite)
	userlib.DatastoreSet(node.Invite, serial)

	return nil

}

func authenticateFile(userdata *User, shared *SharedFile) (bool) {
	ok, _ := findUser(shared.TreeID, userdata.Username)
	return ok
}