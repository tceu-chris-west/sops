// Code generated by protoc-gen-go. DO NOT EDIT.
// source: keyservice/keyservice.proto

package keyservice

import (
	context "context"
	fmt "fmt"
	proto "github.com/golang/protobuf/proto"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
	math "math"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.ProtoPackageIsVersion3 // please upgrade the proto package

type Key struct {
	// Types that are valid to be assigned to KeyType:
	//	*Key_KmsKey
	//	*Key_PgpKey
	//	*Key_GcpKmsKey
	//	*Key_AzureKeyvaultKey
	//	*Key_VaultKey
	//	*Key_AgeKey
	//	*Key_YandexKmsKey
	KeyType              isKey_KeyType `protobuf_oneof:"key_type"`
	XXX_NoUnkeyedLiteral struct{}      `json:"-"`
	XXX_unrecognized     []byte        `json:"-"`
	XXX_sizecache        int32         `json:"-"`
}

func (m *Key) Reset()         { *m = Key{} }
func (m *Key) String() string { return proto.CompactTextString(m) }
func (*Key) ProtoMessage()    {}
func (*Key) Descriptor() ([]byte, []int) {
	return fileDescriptor_8c1e2c407c293790, []int{0}
}

func (m *Key) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_Key.Unmarshal(m, b)
}
func (m *Key) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_Key.Marshal(b, m, deterministic)
}
func (m *Key) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Key.Merge(m, src)
}
func (m *Key) XXX_Size() int {
	return xxx_messageInfo_Key.Size(m)
}
func (m *Key) XXX_DiscardUnknown() {
	xxx_messageInfo_Key.DiscardUnknown(m)
}

var xxx_messageInfo_Key proto.InternalMessageInfo

type isKey_KeyType interface {
	isKey_KeyType()
}

type Key_KmsKey struct {
	KmsKey *KmsKey `protobuf:"bytes,1,opt,name=kms_key,json=kmsKey,proto3,oneof"`
}

type Key_PgpKey struct {
	PgpKey *PgpKey `protobuf:"bytes,2,opt,name=pgp_key,json=pgpKey,proto3,oneof"`
}

type Key_GcpKmsKey struct {
	GcpKmsKey *GcpKmsKey `protobuf:"bytes,3,opt,name=gcp_kms_key,json=gcpKmsKey,proto3,oneof"`
}

type Key_AzureKeyvaultKey struct {
	AzureKeyvaultKey *AzureKeyVaultKey `protobuf:"bytes,4,opt,name=azure_keyvault_key,json=azureKeyvaultKey,proto3,oneof"`
}

type Key_VaultKey struct {
	VaultKey *VaultKey `protobuf:"bytes,5,opt,name=vault_key,json=vaultKey,proto3,oneof"`
}

type Key_AgeKey struct {
	AgeKey *AgeKey `protobuf:"bytes,6,opt,name=age_key,json=ageKey,proto3,oneof"`
}

type Key_YandexKmsKey struct {
	YandexKmsKey *YandexKmsKey `protobuf:"bytes,7,opt,name=yandex_kms_key,json=yandexKmsKey,proto3,oneof"`
}

func (*Key_KmsKey) isKey_KeyType() {}

func (*Key_PgpKey) isKey_KeyType() {}

func (*Key_GcpKmsKey) isKey_KeyType() {}

func (*Key_AzureKeyvaultKey) isKey_KeyType() {}

func (*Key_VaultKey) isKey_KeyType() {}

func (*Key_AgeKey) isKey_KeyType() {}

func (*Key_YandexKmsKey) isKey_KeyType() {}

func (m *Key) GetKeyType() isKey_KeyType {
	if m != nil {
		return m.KeyType
	}
	return nil
}

func (m *Key) GetKmsKey() *KmsKey {
	if x, ok := m.GetKeyType().(*Key_KmsKey); ok {
		return x.KmsKey
	}
	return nil
}

func (m *Key) GetPgpKey() *PgpKey {
	if x, ok := m.GetKeyType().(*Key_PgpKey); ok {
		return x.PgpKey
	}
	return nil
}

func (m *Key) GetGcpKmsKey() *GcpKmsKey {
	if x, ok := m.GetKeyType().(*Key_GcpKmsKey); ok {
		return x.GcpKmsKey
	}
	return nil
}

func (m *Key) GetAzureKeyvaultKey() *AzureKeyVaultKey {
	if x, ok := m.GetKeyType().(*Key_AzureKeyvaultKey); ok {
		return x.AzureKeyvaultKey
	}
	return nil
}

func (m *Key) GetVaultKey() *VaultKey {
	if x, ok := m.GetKeyType().(*Key_VaultKey); ok {
		return x.VaultKey
	}
	return nil
}

func (m *Key) GetAgeKey() *AgeKey {
	if x, ok := m.GetKeyType().(*Key_AgeKey); ok {
		return x.AgeKey
	}
	return nil
}

func (m *Key) GetYandexKmsKey() *YandexKmsKey {
	if x, ok := m.GetKeyType().(*Key_YandexKmsKey); ok {
		return x.YandexKmsKey
	}
	return nil
}

// XXX_OneofWrappers is for the internal use of the proto package.
func (*Key) XXX_OneofWrappers() []interface{} {
	return []interface{}{
		(*Key_KmsKey)(nil),
		(*Key_PgpKey)(nil),
		(*Key_GcpKmsKey)(nil),
		(*Key_AzureKeyvaultKey)(nil),
		(*Key_VaultKey)(nil),
		(*Key_AgeKey)(nil),
		(*Key_YandexKmsKey)(nil),
	}
}

type PgpKey struct {
	Fingerprint          string   `protobuf:"bytes,1,opt,name=fingerprint,proto3" json:"fingerprint,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *PgpKey) Reset()         { *m = PgpKey{} }
func (m *PgpKey) String() string { return proto.CompactTextString(m) }
func (*PgpKey) ProtoMessage()    {}
func (*PgpKey) Descriptor() ([]byte, []int) {
	return fileDescriptor_8c1e2c407c293790, []int{1}
}

func (m *PgpKey) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_PgpKey.Unmarshal(m, b)
}
func (m *PgpKey) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_PgpKey.Marshal(b, m, deterministic)
}
func (m *PgpKey) XXX_Merge(src proto.Message) {
	xxx_messageInfo_PgpKey.Merge(m, src)
}
func (m *PgpKey) XXX_Size() int {
	return xxx_messageInfo_PgpKey.Size(m)
}
func (m *PgpKey) XXX_DiscardUnknown() {
	xxx_messageInfo_PgpKey.DiscardUnknown(m)
}

var xxx_messageInfo_PgpKey proto.InternalMessageInfo

func (m *PgpKey) GetFingerprint() string {
	if m != nil {
		return m.Fingerprint
	}
	return ""
}

type KmsKey struct {
	Arn                  string            `protobuf:"bytes,1,opt,name=arn,proto3" json:"arn,omitempty"`
	Role                 string            `protobuf:"bytes,2,opt,name=role,proto3" json:"role,omitempty"`
	Context              map[string]string `protobuf:"bytes,3,rep,name=context,proto3" json:"context,omitempty" protobuf_key:"bytes,1,opt,name=key,proto3" protobuf_val:"bytes,2,opt,name=value,proto3"`
	AwsProfile           string            `protobuf:"bytes,4,opt,name=aws_profile,json=awsProfile,proto3" json:"aws_profile,omitempty"`
	XXX_NoUnkeyedLiteral struct{}          `json:"-"`
	XXX_unrecognized     []byte            `json:"-"`
	XXX_sizecache        int32             `json:"-"`
}

func (m *KmsKey) Reset()         { *m = KmsKey{} }
func (m *KmsKey) String() string { return proto.CompactTextString(m) }
func (*KmsKey) ProtoMessage()    {}
func (*KmsKey) Descriptor() ([]byte, []int) {
	return fileDescriptor_8c1e2c407c293790, []int{2}
}

func (m *KmsKey) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_KmsKey.Unmarshal(m, b)
}
func (m *KmsKey) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_KmsKey.Marshal(b, m, deterministic)
}
func (m *KmsKey) XXX_Merge(src proto.Message) {
	xxx_messageInfo_KmsKey.Merge(m, src)
}
func (m *KmsKey) XXX_Size() int {
	return xxx_messageInfo_KmsKey.Size(m)
}
func (m *KmsKey) XXX_DiscardUnknown() {
	xxx_messageInfo_KmsKey.DiscardUnknown(m)
}

var xxx_messageInfo_KmsKey proto.InternalMessageInfo

func (m *KmsKey) GetArn() string {
	if m != nil {
		return m.Arn
	}
	return ""
}

func (m *KmsKey) GetRole() string {
	if m != nil {
		return m.Role
	}
	return ""
}

func (m *KmsKey) GetContext() map[string]string {
	if m != nil {
		return m.Context
	}
	return nil
}

func (m *KmsKey) GetAwsProfile() string {
	if m != nil {
		return m.AwsProfile
	}
	return ""
}

type GcpKmsKey struct {
	ResourceId           string   `protobuf:"bytes,1,opt,name=resource_id,json=resourceId,proto3" json:"resource_id,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *GcpKmsKey) Reset()         { *m = GcpKmsKey{} }
func (m *GcpKmsKey) String() string { return proto.CompactTextString(m) }
func (*GcpKmsKey) ProtoMessage()    {}
func (*GcpKmsKey) Descriptor() ([]byte, []int) {
	return fileDescriptor_8c1e2c407c293790, []int{3}
}

func (m *GcpKmsKey) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_GcpKmsKey.Unmarshal(m, b)
}
func (m *GcpKmsKey) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_GcpKmsKey.Marshal(b, m, deterministic)
}
func (m *GcpKmsKey) XXX_Merge(src proto.Message) {
	xxx_messageInfo_GcpKmsKey.Merge(m, src)
}
func (m *GcpKmsKey) XXX_Size() int {
	return xxx_messageInfo_GcpKmsKey.Size(m)
}
func (m *GcpKmsKey) XXX_DiscardUnknown() {
	xxx_messageInfo_GcpKmsKey.DiscardUnknown(m)
}

var xxx_messageInfo_GcpKmsKey proto.InternalMessageInfo

func (m *GcpKmsKey) GetResourceId() string {
	if m != nil {
		return m.ResourceId
	}
	return ""
}

type VaultKey struct {
	VaultAddress         string   `protobuf:"bytes,1,opt,name=vault_address,json=vaultAddress,proto3" json:"vault_address,omitempty"`
	EnginePath           string   `protobuf:"bytes,2,opt,name=engine_path,json=enginePath,proto3" json:"engine_path,omitempty"`
	KeyName              string   `protobuf:"bytes,3,opt,name=key_name,json=keyName,proto3" json:"key_name,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *VaultKey) Reset()         { *m = VaultKey{} }
func (m *VaultKey) String() string { return proto.CompactTextString(m) }
func (*VaultKey) ProtoMessage()    {}
func (*VaultKey) Descriptor() ([]byte, []int) {
	return fileDescriptor_8c1e2c407c293790, []int{4}
}

func (m *VaultKey) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_VaultKey.Unmarshal(m, b)
}
func (m *VaultKey) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_VaultKey.Marshal(b, m, deterministic)
}
func (m *VaultKey) XXX_Merge(src proto.Message) {
	xxx_messageInfo_VaultKey.Merge(m, src)
}
func (m *VaultKey) XXX_Size() int {
	return xxx_messageInfo_VaultKey.Size(m)
}
func (m *VaultKey) XXX_DiscardUnknown() {
	xxx_messageInfo_VaultKey.DiscardUnknown(m)
}

var xxx_messageInfo_VaultKey proto.InternalMessageInfo

func (m *VaultKey) GetVaultAddress() string {
	if m != nil {
		return m.VaultAddress
	}
	return ""
}

func (m *VaultKey) GetEnginePath() string {
	if m != nil {
		return m.EnginePath
	}
	return ""
}

func (m *VaultKey) GetKeyName() string {
	if m != nil {
		return m.KeyName
	}
	return ""
}

type AzureKeyVaultKey struct {
	VaultUrl             string   `protobuf:"bytes,1,opt,name=vault_url,json=vaultUrl,proto3" json:"vault_url,omitempty"`
	Name                 string   `protobuf:"bytes,2,opt,name=name,proto3" json:"name,omitempty"`
	Version              string   `protobuf:"bytes,3,opt,name=version,proto3" json:"version,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *AzureKeyVaultKey) Reset()         { *m = AzureKeyVaultKey{} }
func (m *AzureKeyVaultKey) String() string { return proto.CompactTextString(m) }
func (*AzureKeyVaultKey) ProtoMessage()    {}
func (*AzureKeyVaultKey) Descriptor() ([]byte, []int) {
	return fileDescriptor_8c1e2c407c293790, []int{5}
}

func (m *AzureKeyVaultKey) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_AzureKeyVaultKey.Unmarshal(m, b)
}
func (m *AzureKeyVaultKey) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_AzureKeyVaultKey.Marshal(b, m, deterministic)
}
func (m *AzureKeyVaultKey) XXX_Merge(src proto.Message) {
	xxx_messageInfo_AzureKeyVaultKey.Merge(m, src)
}
func (m *AzureKeyVaultKey) XXX_Size() int {
	return xxx_messageInfo_AzureKeyVaultKey.Size(m)
}
func (m *AzureKeyVaultKey) XXX_DiscardUnknown() {
	xxx_messageInfo_AzureKeyVaultKey.DiscardUnknown(m)
}

var xxx_messageInfo_AzureKeyVaultKey proto.InternalMessageInfo

func (m *AzureKeyVaultKey) GetVaultUrl() string {
	if m != nil {
		return m.VaultUrl
	}
	return ""
}

func (m *AzureKeyVaultKey) GetName() string {
	if m != nil {
		return m.Name
	}
	return ""
}

func (m *AzureKeyVaultKey) GetVersion() string {
	if m != nil {
		return m.Version
	}
	return ""
}

type AgeKey struct {
	Recipient            string   `protobuf:"bytes,1,opt,name=recipient,proto3" json:"recipient,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *AgeKey) Reset()         { *m = AgeKey{} }
func (m *AgeKey) String() string { return proto.CompactTextString(m) }
func (*AgeKey) ProtoMessage()    {}
func (*AgeKey) Descriptor() ([]byte, []int) {
	return fileDescriptor_8c1e2c407c293790, []int{6}
}

func (m *AgeKey) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_AgeKey.Unmarshal(m, b)
}
func (m *AgeKey) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_AgeKey.Marshal(b, m, deterministic)
}
func (m *AgeKey) XXX_Merge(src proto.Message) {
	xxx_messageInfo_AgeKey.Merge(m, src)
}
func (m *AgeKey) XXX_Size() int {
	return xxx_messageInfo_AgeKey.Size(m)
}
func (m *AgeKey) XXX_DiscardUnknown() {
	xxx_messageInfo_AgeKey.DiscardUnknown(m)
}

var xxx_messageInfo_AgeKey proto.InternalMessageInfo

func (m *AgeKey) GetRecipient() string {
	if m != nil {
		return m.Recipient
	}
	return ""
}

type YandexKmsKey struct {
	KeyId                string   `protobuf:"bytes,1,opt,name=key_id,json=keyId,proto3" json:"key_id,omitempty"`
	SaKeyFile            string   `protobuf:"bytes,2,opt,name=sa_key_file,json=saKeyFile,proto3" json:"sa_key_file,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *YandexKmsKey) Reset()         { *m = YandexKmsKey{} }
func (m *YandexKmsKey) String() string { return proto.CompactTextString(m) }
func (*YandexKmsKey) ProtoMessage()    {}
func (*YandexKmsKey) Descriptor() ([]byte, []int) {
	return fileDescriptor_8c1e2c407c293790, []int{7}
}

func (m *YandexKmsKey) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_YandexKmsKey.Unmarshal(m, b)
}
func (m *YandexKmsKey) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_YandexKmsKey.Marshal(b, m, deterministic)
}
func (m *YandexKmsKey) XXX_Merge(src proto.Message) {
	xxx_messageInfo_YandexKmsKey.Merge(m, src)
}
func (m *YandexKmsKey) XXX_Size() int {
	return xxx_messageInfo_YandexKmsKey.Size(m)
}
func (m *YandexKmsKey) XXX_DiscardUnknown() {
	xxx_messageInfo_YandexKmsKey.DiscardUnknown(m)
}

var xxx_messageInfo_YandexKmsKey proto.InternalMessageInfo

func (m *YandexKmsKey) GetKeyId() string {
	if m != nil {
		return m.KeyId
	}
	return ""
}

func (m *YandexKmsKey) GetSaKeyFile() string {
	if m != nil {
		return m.SaKeyFile
	}
	return ""
}

type EncryptRequest struct {
	Key                  *Key     `protobuf:"bytes,1,opt,name=key,proto3" json:"key,omitempty"`
	Plaintext            []byte   `protobuf:"bytes,2,opt,name=plaintext,proto3" json:"plaintext,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *EncryptRequest) Reset()         { *m = EncryptRequest{} }
func (m *EncryptRequest) String() string { return proto.CompactTextString(m) }
func (*EncryptRequest) ProtoMessage()    {}
func (*EncryptRequest) Descriptor() ([]byte, []int) {
	return fileDescriptor_8c1e2c407c293790, []int{8}
}

func (m *EncryptRequest) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_EncryptRequest.Unmarshal(m, b)
}
func (m *EncryptRequest) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_EncryptRequest.Marshal(b, m, deterministic)
}
func (m *EncryptRequest) XXX_Merge(src proto.Message) {
	xxx_messageInfo_EncryptRequest.Merge(m, src)
}
func (m *EncryptRequest) XXX_Size() int {
	return xxx_messageInfo_EncryptRequest.Size(m)
}
func (m *EncryptRequest) XXX_DiscardUnknown() {
	xxx_messageInfo_EncryptRequest.DiscardUnknown(m)
}

var xxx_messageInfo_EncryptRequest proto.InternalMessageInfo

func (m *EncryptRequest) GetKey() *Key {
	if m != nil {
		return m.Key
	}
	return nil
}

func (m *EncryptRequest) GetPlaintext() []byte {
	if m != nil {
		return m.Plaintext
	}
	return nil
}

type EncryptResponse struct {
	Ciphertext           []byte   `protobuf:"bytes,1,opt,name=ciphertext,proto3" json:"ciphertext,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *EncryptResponse) Reset()         { *m = EncryptResponse{} }
func (m *EncryptResponse) String() string { return proto.CompactTextString(m) }
func (*EncryptResponse) ProtoMessage()    {}
func (*EncryptResponse) Descriptor() ([]byte, []int) {
	return fileDescriptor_8c1e2c407c293790, []int{9}
}

func (m *EncryptResponse) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_EncryptResponse.Unmarshal(m, b)
}
func (m *EncryptResponse) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_EncryptResponse.Marshal(b, m, deterministic)
}
func (m *EncryptResponse) XXX_Merge(src proto.Message) {
	xxx_messageInfo_EncryptResponse.Merge(m, src)
}
func (m *EncryptResponse) XXX_Size() int {
	return xxx_messageInfo_EncryptResponse.Size(m)
}
func (m *EncryptResponse) XXX_DiscardUnknown() {
	xxx_messageInfo_EncryptResponse.DiscardUnknown(m)
}

var xxx_messageInfo_EncryptResponse proto.InternalMessageInfo

func (m *EncryptResponse) GetCiphertext() []byte {
	if m != nil {
		return m.Ciphertext
	}
	return nil
}

type DecryptRequest struct {
	Key                  *Key     `protobuf:"bytes,1,opt,name=key,proto3" json:"key,omitempty"`
	Ciphertext           []byte   `protobuf:"bytes,2,opt,name=ciphertext,proto3" json:"ciphertext,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *DecryptRequest) Reset()         { *m = DecryptRequest{} }
func (m *DecryptRequest) String() string { return proto.CompactTextString(m) }
func (*DecryptRequest) ProtoMessage()    {}
func (*DecryptRequest) Descriptor() ([]byte, []int) {
	return fileDescriptor_8c1e2c407c293790, []int{10}
}

func (m *DecryptRequest) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_DecryptRequest.Unmarshal(m, b)
}
func (m *DecryptRequest) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_DecryptRequest.Marshal(b, m, deterministic)
}
func (m *DecryptRequest) XXX_Merge(src proto.Message) {
	xxx_messageInfo_DecryptRequest.Merge(m, src)
}
func (m *DecryptRequest) XXX_Size() int {
	return xxx_messageInfo_DecryptRequest.Size(m)
}
func (m *DecryptRequest) XXX_DiscardUnknown() {
	xxx_messageInfo_DecryptRequest.DiscardUnknown(m)
}

var xxx_messageInfo_DecryptRequest proto.InternalMessageInfo

func (m *DecryptRequest) GetKey() *Key {
	if m != nil {
		return m.Key
	}
	return nil
}

func (m *DecryptRequest) GetCiphertext() []byte {
	if m != nil {
		return m.Ciphertext
	}
	return nil
}

type DecryptResponse struct {
	Plaintext            []byte   `protobuf:"bytes,1,opt,name=plaintext,proto3" json:"plaintext,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *DecryptResponse) Reset()         { *m = DecryptResponse{} }
func (m *DecryptResponse) String() string { return proto.CompactTextString(m) }
func (*DecryptResponse) ProtoMessage()    {}
func (*DecryptResponse) Descriptor() ([]byte, []int) {
	return fileDescriptor_8c1e2c407c293790, []int{11}
}

func (m *DecryptResponse) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_DecryptResponse.Unmarshal(m, b)
}
func (m *DecryptResponse) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_DecryptResponse.Marshal(b, m, deterministic)
}
func (m *DecryptResponse) XXX_Merge(src proto.Message) {
	xxx_messageInfo_DecryptResponse.Merge(m, src)
}
func (m *DecryptResponse) XXX_Size() int {
	return xxx_messageInfo_DecryptResponse.Size(m)
}
func (m *DecryptResponse) XXX_DiscardUnknown() {
	xxx_messageInfo_DecryptResponse.DiscardUnknown(m)
}

var xxx_messageInfo_DecryptResponse proto.InternalMessageInfo

func (m *DecryptResponse) GetPlaintext() []byte {
	if m != nil {
		return m.Plaintext
	}
	return nil
}

func init() {
	proto.RegisterType((*Key)(nil), "Key")
	proto.RegisterType((*PgpKey)(nil), "PgpKey")
	proto.RegisterType((*KmsKey)(nil), "KmsKey")
	proto.RegisterMapType((map[string]string)(nil), "KmsKey.ContextEntry")
	proto.RegisterType((*GcpKmsKey)(nil), "GcpKmsKey")
	proto.RegisterType((*VaultKey)(nil), "VaultKey")
	proto.RegisterType((*AzureKeyVaultKey)(nil), "AzureKeyVaultKey")
	proto.RegisterType((*AgeKey)(nil), "AgeKey")
	proto.RegisterType((*YandexKmsKey)(nil), "YandexKmsKey")
	proto.RegisterType((*EncryptRequest)(nil), "EncryptRequest")
	proto.RegisterType((*EncryptResponse)(nil), "EncryptResponse")
	proto.RegisterType((*DecryptRequest)(nil), "DecryptRequest")
	proto.RegisterType((*DecryptResponse)(nil), "DecryptResponse")
}

func init() {
	proto.RegisterFile("keyservice/keyservice.proto", fileDescriptor_8c1e2c407c293790)
}

var fileDescriptor_8c1e2c407c293790 = []byte{
	// 664 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x8c, 0x54, 0x5d, 0x6b, 0x13, 0x41,
	0x14, 0x6d, 0x92, 0x36, 0xe9, 0xde, 0xa4, 0x4d, 0x1c, 0xaa, 0xc4, 0xb6, 0xd4, 0x32, 0x82, 0x14,
	0x29, 0x5b, 0x8c, 0x08, 0xd2, 0xb7, 0xa8, 0xad, 0x2d, 0x01, 0x29, 0x2b, 0x0a, 0x3e, 0x48, 0x18,
	0x37, 0xb7, 0xdb, 0x65, 0x37, 0xbb, 0xe3, 0xcc, 0x26, 0xed, 0xf8, 0xd7, 0xfc, 0x11, 0xfe, 0x25,
	0x99, 0x8f, 0xdd, 0x7c, 0xf8, 0xe2, 0xdb, 0x9d, 0xb3, 0xe7, 0x9e, 0xfb, 0x75, 0x58, 0x38, 0x48,
	0x50, 0x49, 0x14, 0xf3, 0x38, 0xc4, 0xb3, 0x45, 0xe8, 0x73, 0x91, 0x17, 0x39, 0xfd, 0x53, 0x87,
	0xc6, 0x08, 0x15, 0xa1, 0xd0, 0x4a, 0xa6, 0x72, 0x9c, 0xa0, 0xea, 0xd7, 0x8e, 0x6b, 0x27, 0xed,
	0x41, 0xcb, 0x1f, 0x4d, 0xe5, 0x08, 0xd5, 0xd5, 0x46, 0xd0, 0x4c, 0x4c, 0xa4, 0x39, 0x3c, 0xe2,
	0x86, 0x53, 0x77, 0x9c, 0x9b, 0x88, 0x3b, 0x0e, 0x37, 0x11, 0x39, 0x85, 0x76, 0x14, 0xf2, 0x71,
	0xa9, 0xd5, 0x30, 0x3c, 0xf0, 0x3f, 0x86, 0xbc, 0x92, 0xf3, 0xa2, 0xf2, 0x41, 0x86, 0x40, 0xd8,
	0xaf, 0x99, 0x40, 0xcd, 0x9d, 0xb3, 0x59, 0x5a, 0x98, 0xa4, 0x4d, 0x93, 0xf4, 0xc8, 0x1f, 0xea,
	0x4f, 0x23, 0x54, 0x5f, 0xf5, 0x17, 0x9b, 0xdb, 0x63, 0x0e, 0x9b, 0x3b, 0x8c, 0x9c, 0x80, 0xb7,
	0xc8, 0xdc, 0x32, 0x99, 0x9e, 0xbf, 0x94, 0xb1, 0x5d, 0x31, 0x29, 0xb4, 0x58, 0x64, 0x4a, 0xf5,
	0x9b, 0xae, 0xfd, 0x61, 0x84, 0xae, 0x7d, 0x66, 0x22, 0xf2, 0x06, 0x76, 0x15, 0xcb, 0x26, 0xf8,
	0x50, 0x4d, 0xd0, 0x32, 0xd4, 0x1d, 0xff, 0x9b, 0x81, 0xab, 0x21, 0x3a, 0x6a, 0xe9, 0xfd, 0x0e,
	0x60, 0x3b, 0x41, 0x35, 0x2e, 0x14, 0x47, 0xfa, 0x12, 0x9a, 0x76, 0x2b, 0xe4, 0x18, 0xda, 0xb7,
	0x71, 0x16, 0xa1, 0xe0, 0x22, 0xce, 0x0a, 0xb3, 0x57, 0x2f, 0x58, 0x86, 0xe8, 0xef, 0x1a, 0x34,
	0xdd, 0x2a, 0x7a, 0xd0, 0x60, 0x22, 0x73, 0x24, 0x1d, 0x12, 0x02, 0x9b, 0x22, 0x4f, 0xd1, 0xec,
	0xda, 0x0b, 0x4c, 0x4c, 0x7c, 0x68, 0x85, 0x79, 0x56, 0xe0, 0x43, 0xd1, 0x6f, 0x1c, 0x37, 0x4e,
	0xda, 0x83, 0x3d, 0x77, 0x26, 0xff, 0xbd, 0x85, 0x2f, 0xb2, 0x42, 0xa8, 0xa0, 0x24, 0x91, 0x67,
	0xd0, 0x66, 0xf7, 0x72, 0xcc, 0x45, 0x7e, 0x1b, 0xa7, 0x68, 0x36, 0xeb, 0x05, 0xc0, 0xee, 0xe5,
	0x8d, 0x45, 0xf6, 0xcf, 0xa1, 0xb3, 0x9c, 0xa9, 0xdb, 0x28, 0x3d, 0xe0, 0x05, 0x3a, 0x24, 0x7b,
	0xb0, 0x35, 0x67, 0xe9, 0xac, 0xec, 0xc3, 0x3e, 0xce, 0xeb, 0x6f, 0x6b, 0xf4, 0x14, 0xbc, 0xea,
	0xae, 0xba, 0x92, 0x40, 0x99, 0xcf, 0x44, 0x88, 0xe3, 0x78, 0xe2, 0x04, 0xa0, 0x84, 0xae, 0x27,
	0x34, 0x81, 0xed, 0xf2, 0x2c, 0xe4, 0x39, 0xec, 0xd8, 0xa3, 0xb1, 0xc9, 0x44, 0xa0, 0x94, 0x8e,
	0xde, 0x31, 0xe0, 0xd0, 0x62, 0x5a, 0x11, 0xb3, 0x28, 0xce, 0x70, 0xcc, 0x59, 0x71, 0xe7, 0xca,
	0x83, 0x85, 0x6e, 0x58, 0x71, 0x47, 0x9e, 0xda, 0xad, 0x67, 0x6c, 0x8a, 0xc6, 0x68, 0x5e, 0xd0,
	0x4a, 0x50, 0x7d, 0x62, 0x53, 0xa4, 0xdf, 0xa1, 0xb7, 0xee, 0x1e, 0x72, 0x50, 0x3a, 0x65, 0x26,
	0x52, 0x57, 0xd0, 0x9a, 0xe3, 0x8b, 0x48, 0xf5, 0xb2, 0x8d, 0x8e, 0x5b, 0xb6, 0x8e, 0x49, 0x1f,
	0x5a, 0x73, 0x14, 0x32, 0xce, 0xb3, 0x52, 0xde, 0x3d, 0xe9, 0x0b, 0x68, 0x5a, 0xeb, 0x90, 0x43,
	0xf0, 0x04, 0x86, 0x31, 0x8f, 0xb1, 0xba, 0xf0, 0x02, 0xa0, 0x17, 0xd0, 0x59, 0xf6, 0x0d, 0x79,
	0x0c, 0x4d, 0xdd, 0x71, 0xb5, 0x9f, 0xad, 0x04, 0xd5, 0xf5, 0x84, 0x1c, 0x41, 0x5b, 0x32, 0xed,
	0xb6, 0xb1, 0xb9, 0x92, 0xed, 0xc1, 0x93, 0x6c, 0x84, 0xea, 0x32, 0x4e, 0x91, 0x5e, 0xc2, 0xee,
	0x45, 0x16, 0x0a, 0xc5, 0x8b, 0x00, 0x7f, 0xce, 0x50, 0x16, 0xe4, 0xc9, 0xe2, 0x4c, 0xed, 0xc1,
	0xa6, 0x3f, 0x42, 0x65, 0x8f, 0x75, 0x08, 0x1e, 0x4f, 0x59, 0x6c, 0x1d, 0xa2, 0x75, 0x3a, 0xc1,
	0x02, 0xa0, 0xaf, 0xa0, 0x5b, 0xe9, 0x48, 0x9e, 0x67, 0x12, 0xc9, 0x11, 0x40, 0x18, 0xf3, 0x3b,
	0x14, 0x26, 0xa3, 0x66, 0x32, 0x96, 0x10, 0x7a, 0x05, 0xbb, 0x1f, 0xf0, 0xbf, 0x4a, 0xaf, 0x2a,
	0xd5, 0xff, 0x51, 0x3a, 0x83, 0x6e, 0xa5, 0xe4, 0x8a, 0xaf, 0x74, 0x5b, 0x5b, 0xeb, 0x76, 0x90,
	0x02, 0x8c, 0x50, 0x7d, 0xb6, 0xbf, 0x2b, 0xed, 0x7c, 0xd7, 0x3b, 0xe9, 0xfa, 0xab, 0xdb, 0xd8,
	0xef, 0xf9, 0x6b, 0x63, 0xd1, 0x0d, 0xcd, 0x77, 0xe5, 0x48, 0xd7, 0x5f, 0x1d, 0x61, 0xbf, 0xe7,
	0xaf, 0x75, 0x42, 0x37, 0x7e, 0x34, 0xcd, 0xff, 0xf0, 0xf5, 0xdf, 0x00, 0x00, 0x00, 0xff, 0xff,
	0x38, 0x5f, 0x0b, 0x0a, 0x2e, 0x05, 0x00, 0x00,
}

// Reference imports to suppress errors if they are not otherwise used.
var _ context.Context
var _ grpc.ClientConnInterface

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
const _ = grpc.SupportPackageIsVersion6

// KeyServiceClient is the client API for KeyService service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://godoc.org/google.golang.org/grpc#ClientConn.NewStream.
type KeyServiceClient interface {
	Encrypt(ctx context.Context, in *EncryptRequest, opts ...grpc.CallOption) (*EncryptResponse, error)
	Decrypt(ctx context.Context, in *DecryptRequest, opts ...grpc.CallOption) (*DecryptResponse, error)
}

type keyServiceClient struct {
	cc grpc.ClientConnInterface
}

func NewKeyServiceClient(cc grpc.ClientConnInterface) KeyServiceClient {
	return &keyServiceClient{cc}
}

func (c *keyServiceClient) Encrypt(ctx context.Context, in *EncryptRequest, opts ...grpc.CallOption) (*EncryptResponse, error) {
	out := new(EncryptResponse)
	err := c.cc.Invoke(ctx, "/KeyService/Encrypt", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *keyServiceClient) Decrypt(ctx context.Context, in *DecryptRequest, opts ...grpc.CallOption) (*DecryptResponse, error) {
	out := new(DecryptResponse)
	err := c.cc.Invoke(ctx, "/KeyService/Decrypt", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// KeyServiceServer is the server API for KeyService service.
type KeyServiceServer interface {
	Encrypt(context.Context, *EncryptRequest) (*EncryptResponse, error)
	Decrypt(context.Context, *DecryptRequest) (*DecryptResponse, error)
}

// UnimplementedKeyServiceServer can be embedded to have forward compatible implementations.
type UnimplementedKeyServiceServer struct {
}

func (*UnimplementedKeyServiceServer) Encrypt(ctx context.Context, req *EncryptRequest) (*EncryptResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Encrypt not implemented")
}
func (*UnimplementedKeyServiceServer) Decrypt(ctx context.Context, req *DecryptRequest) (*DecryptResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Decrypt not implemented")
}

func RegisterKeyServiceServer(s *grpc.Server, srv KeyServiceServer) {
	s.RegisterService(&_KeyService_serviceDesc, srv)
}

func _KeyService_Encrypt_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(EncryptRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(KeyServiceServer).Encrypt(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/KeyService/Encrypt",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(KeyServiceServer).Encrypt(ctx, req.(*EncryptRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _KeyService_Decrypt_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(DecryptRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(KeyServiceServer).Decrypt(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/KeyService/Decrypt",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(KeyServiceServer).Decrypt(ctx, req.(*DecryptRequest))
	}
	return interceptor(ctx, in, info, handler)
}

var _KeyService_serviceDesc = grpc.ServiceDesc{
	ServiceName: "KeyService",
	HandlerType: (*KeyServiceServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "Encrypt",
			Handler:    _KeyService_Encrypt_Handler,
		},
		{
			MethodName: "Decrypt",
			Handler:    _KeyService_Decrypt_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "keyservice/keyservice.proto",
}
