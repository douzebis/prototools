#@ prototext: protoc
messageRp {  #@ repeated SwissArmyKnife = 51
 stringRp: "hello1"  #@ repeated string = 49
 stringRp: "hello2"  #@ repeated string = 49; len_ohb: 3
 stringRp: "hello3"  #@ repeated string = 49
}
messageRp {  #@ repeated SwissArmyKnife = 51
 49: ""  #@ INVALID_LEN
}
messageRp {  #@ repeated SwissArmyKnife = 51
 49: "\200"  #@ INVALID_LEN
}
messageRp {  #@ repeated SwissArmyKnife = 51
 49: ""  #@ TRUNCATED_BYTES; MISSING: 1
}
