#@ prototext: protoc
31 {  #@ group
 1: "group posing as message"  #@ bytes
 2: 42  #@ varint
}
30: "\202\010\000"  #@ bytes
24: "\001\002\003"  #@ bytes
messageRp {  #@ repeated SwissArmyKnife = 51
 stringOp: "clean nested"  #@ string = 29
}
