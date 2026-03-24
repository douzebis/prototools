#@ prototext: protoc
#@ repeated sfixed64 [packed=true] = 96; pack_size: 0
#@ repeated int64 [packed=true] = 83; pack_size: 0
int64Pk: 4  #@ repeated int64 [packed=true] = 83; pack_size: 1
int64Pk: 1  #@ repeated int64 [packed=true] = 83; pack_size: 4; ohb: 3
int64Pk: 2  #@ repeated int64 [packed=true] = 83
int64Pk: 3  #@ repeated int64 [packed=true] = 83
int64Pk: 4  #@ repeated int64 [packed=true] = 83
1: 4  #@ varint
0: 0x02010405a2040302  #@ fixed64; TAG_OOR
0 {  #@ group; TAG_OOR; ETAG_OOR
}
int32Pk: 1  #@ repeated int32 [packed=true] = 85; pack_size: 4
int32Pk: 2  #@ repeated int32 [packed=true] = 85
int32Pk: 3  #@ repeated int32 [packed=true] = 85
int32Pk: 4  #@ repeated int32 [packed=true] = 85
85: "\200\200\200\200\020\002\003\004"  #@ INVALID_PACKED_RECORDS
boolPk: true  #@ repeated bool [packed=true] = 88; pack_size: 4
boolPk: true  #@ repeated bool [packed=true] = 88
boolPk: true  #@ repeated bool [packed=true] = 88
boolPk: true  #@ repeated bool [packed=true] = 88
uint32Pk: 1  #@ repeated uint32 [packed=true] = 93; pack_size: 4
uint32Pk: 2  #@ repeated uint32 [packed=true] = 93
uint32Pk: 3  #@ repeated uint32 [packed=true] = 93
uint32Pk: 4  #@ repeated uint32 [packed=true] = 93
int32Pk: 1  #@ repeated int32 [packed=true] = 85; pack_size: 4
int32Pk: 2  #@ repeated int32 [packed=true] = 85
int32Pk: 3  #@ repeated int32 [packed=true] = 85
int32Pk: 4  #@ repeated int32 [packed=true] = 85
sint32Pk: 1  #@ repeated sint32 [packed=true] = 97; pack_size: 4
sint32Pk: 2  #@ repeated sint32 [packed=true] = 97
sint32Pk: 3  #@ repeated sint32 [packed=true] = 97
sint32Pk: 4  #@ repeated sint32 [packed=true] = 97
sint64Pk: 1  #@ repeated sint64 [packed=true] = 98; pack_size: 4
sint64Pk: 2  #@ repeated sint64 [packed=true] = 98
sint64Pk: 3  #@ repeated sint64 [packed=true] = 98
sint64Pk: 4  #@ repeated sint64 [packed=true] = 98
