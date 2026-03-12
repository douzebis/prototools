#@ prototext: protoc
sfixed64Pk: []  #@ repeated sfixed64 [packed=true] = 96
int64Pk: []  #@ repeated int64 [packed=true] = 83
int64Pk: [4]  #@ repeated int64 [packed=true] = 83
int64Pk: [1, 2, 3, 4]  #@ repeated int64 [packed=true] = 83; packed_ohb: [3, 0, 0, 0]
1: 4  #@ varint
0: 0x02010405a2040302  #@ fixed64; TAG_OOR
0 {  #@ group; TAG_OOR; ETAG_OOR
}
int32Pk: [1, 2, 3, 4]  #@ repeated int32 [packed=true] = 85
85: "\200\200\200\200\020\002\003\004"  #@ INVALID_PACKED_RECORDS
boolPk: [true, true, true, true]  #@ repeated bool [packed=true] = 88
uint32Pk: [1, 2, 3, 4]  #@ repeated uint32 [packed=true] = 93
int32Pk: [1, 2, 3, 4]  #@ repeated int32 [packed=true] = 85
sint32Pk: [1, 2, 3, 4]  #@ repeated sint32 [packed=true] = 97
sint64Pk: [1, 2, 3, 4]  #@ repeated sint64 [packed=true] = 98
