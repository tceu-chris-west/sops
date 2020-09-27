package yandexkms

import (
	"time"
	"context"
	"strings"

	"go.mozilla.org/sops/v3/logging"
	"github.com/sirupsen/logrus"
	"github.com/yandex-cloud/go-genproto/yandex/cloud/kms/v1"
	ycsdk "github.com/yandex-cloud/go-sdk"
)

var log *logrus.Logger

func init() {
	log = logging.NewLogger("YANDEXKMS")
}

// Borrowing from the AWS KMS keysource
var kmsSvc ycsdk.SDK
var isMocked bool

// MasterKey is a Yandex KMS key used to encrypt and decrypt sops' data key.
type MasterKey struct {
	KeyId             string
	EncryptedKey      string
	CreationDate      time.Time
	Token             string
}

// NewMasterKeyFromResourceID takes a Yandex KMS key ID string and returns a new MasterKey for that
func NewMasterKeyFromKeyID(keyId string) *MasterKey {
	k := &MasterKey{}
	k.KeyId = keyId
	k.CreationDate = time.Now().UTC()
	return k
}

// MasterKeysFromResourceIDString takes a comma separated list of Yandex KMS key IDs and returns a slice of new MasterKeys for them
func MasterKeysFromKeyIDString(keyId string) []*MasterKey {
	var keys []*MasterKey
	if keyId == "" {
		return keys
	}
	for _, s := range strings.Split(keyId, ",") {
		keys = append(keys, NewMasterKeyFromKeyID(s))
	}
	return keys
}

// EncryptedDataKey returns the encrypted data key this master key holds
func (key *MasterKey) EncryptedDataKey() []byte {
	return []byte(key.EncryptedKey)
}

// SetEncryptedDataKey sets the encrypted data key for this master key
func (key *MasterKey) SetEncryptedDataKey(enc []byte) {
	key.EncryptedKey = string(enc)
}

// Encrypt takes a sops data key, encrypts it with KMS and stores the result in the EncryptedKey field
func (key *MasterKey) Encrypt(dataKey []byte) error {
	ctx := context.Background()
	sdk, err := key.createSession(ctx)
	if err != nil {
		return err
	}

	response, err := sdk.KMSCrypto().SymmetricCrypto().Encrypt(ctx, &kms.SymmetricEncryptRequest{
		KeyId:      key.KeyId,
		Plaintext:  dataKey,
		AadContext: key.aadContext(),
	})
	if err != nil {
		return err
	}

	key.EncryptedKey = string(response.Ciphertext[:])
	return nil
}

// EncryptIfNeeded encrypts the provided sops' data key and encrypts it if it hasn't been encrypted yet
func (key *MasterKey) EncryptIfNeeded(dataKey []byte) error {
	if key.EncryptedKey == "" {
		return key.Encrypt(dataKey)
	}
	return nil
}

// Decrypt decrypts the EncryptedKey field with Yandex KMS and returns the result.
func (key *MasterKey) Decrypt() ([]byte, error) {
	ctx := context.Background()
	sdk, err := key.createSession(ctx)
	if err != nil {
		return nil, err
	}

	response, err := sdk.KMSCrypto().SymmetricCrypto().Decrypt(ctx, &kms.SymmetricDecryptRequest{
		KeyId:      key.KeyId,
		Ciphertext: []byte(key.EncryptedKey),
		AadContext: key.aadContext(),
	})
	if err != nil {
		return nil, err
	}

	return response.Plaintext, nil
}

// NeedsRotation returns whether the data key needs to be rotated or not.
func (key *MasterKey) NeedsRotation() bool {
	return time.Since(key.CreationDate) > (time.Hour * 24 * 30 * 6)
}

// ToString converts the key to a string representation
func (key *MasterKey) ToString() string {
	return key.KeyId
}

// ToMap converts the MasterKey to a map for serialization purposes
func (key MasterKey) ToMap() map[string]interface{} {
	out := make(map[string]interface{})
	out["created_at"] = key.CreationDate.UTC().Format(time.RFC3339)
	out["enc"] = key.EncryptedKey
	out["key_id"] = key.KeyId
	// possibly not a good idea to put OAuth tokens in serialised data
	return out
}

// authenticate with Yandex
func (key MasterKey) createSession(ctx context.Context) (*ycsdk.SDK, error) {
	var credentials ycsdk.Credentials

	if key.Token != "" {
		// if there's an OAuth token, use it
		credentials = ycsdk.OAuthToken(key.Token)
	} else {
		// else look for an instance service account
		credentials = ycsdk.InstanceServiceAccount()
	}

	sdk, err := ycsdk.Build(ctx, ycsdk.Config{
		Credentials: credentials,
	})

	if err != nil {
		return nil, err
	}

	return sdk, nil
}

// derive an AAD context, see: https://cloud.yandex.com/docs/kms/concepts/encryption#add-context
func (key MasterKey) aadContext() ([]byte) {
	//return []byte(key.CreationDate.UTC().Format(time.RFC3339))
	return []byte("TODO")
}
