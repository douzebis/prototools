#@ prototext: protoc
int32Op: 3  #@ int32 = 25
GroupOp {  #@ group; GroupOp = 30
 uint64Op: 10  #@ uint64 = 130
 9000: 99  #@ varint
}
messageOp {  #@ SwissArmyKnife = 31
 stringOp: "in messageop"  #@ string = 29
 9001: "unknown bytes inside msg"  #@ bytes
}
999 {  #@ group
 1: 7  #@ varint
 2: "in unknown group"  #@ bytes
}
1000: "unknown message-like bytes"  #@ bytes
421: "\320\0027\273>\010\010\274>"  #@ bytes
