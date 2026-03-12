#@ prototext: protoc
int32Op: 42  #@ int32 = 25
GroupOp {  #@ group; GroupOp = 30
 uint64Op: 111  #@ uint64 = 130
}
GroupRp {  #@ group; repeated GroupRp = 50
 uint64Op: 10  #@ uint64 = 150
}
GroupRp {  #@ group; repeated GroupRp = 50
 uint64Op: 20  #@ uint64 = 150
}
