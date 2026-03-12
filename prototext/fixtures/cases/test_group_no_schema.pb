#@ prototext: protoc
GroupRp {  #@ group; repeated GroupRp = 50
 uint64Op: 1  #@ uint64 = 150
 uint64Op: 2  #@ uint64 = 150
 uint64Op: 3  #@ uint64 = 150
 uint64Op: 4  #@ uint64 = 150; val_ohb: 3
 1: "no schema for these bytes."  #@ bytes
}
GROUP {  #@ group; GROUP = 13
 1: 1  #@ varint
 1: 2  #@ varint
 1: 3  #@ varint
 1: 4  #@ varint; val_ohb: 3
}
