package main

import (
	reflect "reflect"
	sync "sync"

	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

type MigrationPayload struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	OtpParameters []*OtpParameters `protobuf:"bytes,1,rep,name=otp_parameters,json=otpParameters,proto3" json:"otp_parameters,omitempty"`
}

func (x *MigrationPayload) Reset() {
	*x = MigrationPayload{}
	if protoimpl.UnsafeEnabled {
		mi := &file_migration_payload_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *MigrationPayload) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*MigrationPayload) ProtoMessage() {}

func (x *MigrationPayload) ProtoReflect() protoreflect.Message {
	mi := &file_migration_payload_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use MigrationPayload.ProtoReflect.Descriptor instead.
func (*MigrationPayload) Descriptor() ([]byte, []int) {
	return file_migration_payload_proto_rawDescGZIP(), []int{0}
}

func (x *MigrationPayload) GetOtpParameters() []*OtpParameters {
	if x != nil {
		return x.OtpParameters
	}
	return nil
}

type OtpParameters struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	RawData []byte `protobuf:"bytes,1,opt,name=raw_data,json=rawData,proto3" json:"raw_data,omitempty"` // Changed to raw bytes to avoid UTF-8 issues
}

func (x *OtpParameters) Reset() {
	*x = OtpParameters{}
	if protoimpl.UnsafeEnabled {
		mi := &file_migration_payload_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *OtpParameters) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*OtpParameters) ProtoMessage() {}

func (x *OtpParameters) ProtoReflect() protoreflect.Message {
	mi := &file_migration_payload_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use OtpParameters.ProtoReflect.Descriptor instead.
func (*OtpParameters) Descriptor() ([]byte, []int) {
	return file_migration_payload_proto_rawDescGZIP(), []int{1}
}

func (x *OtpParameters) GetRawData() []byte {
	if x != nil {
		return x.RawData
	}
	return nil
}

var File_migration_payload_proto protoreflect.FileDescriptor

var file_migration_payload_proto_rawDesc = []byte{
	0x0a, 0x17, 0x6d, 0x69, 0x67, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x5f, 0x70, 0x61, 0x79, 0x6c,
	0x6f, 0x61, 0x64, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x04, 0x6d, 0x61, 0x69, 0x6e, 0x22,
	0x4e, 0x0a, 0x10, 0x4d, 0x69, 0x67, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x50, 0x61, 0x79, 0x6c,
	0x6f, 0x61, 0x64, 0x12, 0x3a, 0x0a, 0x0e, 0x6f, 0x74, 0x70, 0x5f, 0x70, 0x61, 0x72, 0x61, 0x6d,
	0x65, 0x74, 0x65, 0x72, 0x73, 0x18, 0x01, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x13, 0x2e, 0x6d, 0x61,
	0x69, 0x6e, 0x2e, 0x4f, 0x74, 0x70, 0x50, 0x61, 0x72, 0x61, 0x6d, 0x65, 0x74, 0x65, 0x72, 0x73,
	0x52, 0x0d, 0x6f, 0x74, 0x70, 0x50, 0x61, 0x72, 0x61, 0x6d, 0x65, 0x74, 0x65, 0x72, 0x73, 0x22,
	0x2a, 0x0a, 0x0d, 0x4f, 0x74, 0x70, 0x50, 0x61, 0x72, 0x61, 0x6d, 0x65, 0x74, 0x65, 0x72, 0x73,
	0x12, 0x19, 0x0a, 0x08, 0x72, 0x61, 0x77, 0x5f, 0x64, 0x61, 0x74, 0x61, 0x18, 0x01, 0x20, 0x01,
	0x28, 0x0c, 0x52, 0x07, 0x72, 0x61, 0x77, 0x44, 0x61, 0x74, 0x61, 0x42, 0x04, 0x5a, 0x02, 0x2e,
	0x2f, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_migration_payload_proto_rawDescOnce sync.Once
	file_migration_payload_proto_rawDescData = file_migration_payload_proto_rawDesc
)

func file_migration_payload_proto_rawDescGZIP() []byte {
	file_migration_payload_proto_rawDescOnce.Do(func() {
		file_migration_payload_proto_rawDescData = protoimpl.X.CompressGZIP(file_migration_payload_proto_rawDescData)
	})
	return file_migration_payload_proto_rawDescData
}

var file_migration_payload_proto_msgTypes = make([]protoimpl.MessageInfo, 2)
var file_migration_payload_proto_goTypes = []any{
	(*MigrationPayload)(nil), // 0: main.MigrationPayload
	(*OtpParameters)(nil),    // 1: main.OtpParameters
}
var file_migration_payload_proto_depIdxs = []int32{
	1, // 0: main.MigrationPayload.otp_parameters:type_name -> main.OtpParameters
	1, // [1:1] is the sub-list for method output_type
	1, // [1:1] is the sub-list for method input_type
	1, // [1:1] is the sub-list for extension type_name
	1, // [1:1] is the sub-list for extension extendee
	0, // [0:1] is the sub-list for field type_name
}

func init() { file_migration_payload_proto_init() }
func file_migration_payload_proto_init() {
	if File_migration_payload_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_migration_payload_proto_msgTypes[0].Exporter = func(v any, i int) any {
			switch v := v.(*MigrationPayload); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_migration_payload_proto_msgTypes[1].Exporter = func(v any, i int) any {
			switch v := v.(*OtpParameters); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_migration_payload_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   2,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_migration_payload_proto_goTypes,
		DependencyIndexes: file_migration_payload_proto_depIdxs,
		MessageInfos:      file_migration_payload_proto_msgTypes,
	}.Build()
	File_migration_payload_proto = out.File
	file_migration_payload_proto_rawDesc = nil
	file_migration_payload_proto_goTypes = nil
	file_migration_payload_proto_depIdxs = nil
}
