#@ prototext: protoc
messageRp {  #@ repeated SwissArmyKnife = 51
 stringRp: "Hello, world!"  #@ repeated string = 49
}
messageRp {  #@ repeated SwissArmyKnife = 51
 49: "A vicious hello\300\000"  #@ INVALID_STRING
}
messageRp {  #@ repeated SwissArmyKnife = 51
 49: "Another vicious hello\370\200\200\200"  #@ INVALID_STRING
}
messageRp {  #@ repeated SwissArmyKnife = 51
 49: "And another one\370\200\200\000"  #@ INVALID_STRING
}
messageRp {  #@ repeated SwissArmyKnife = 51
 49: "One more (\370\200\200\000) + overhanging bytes"  #@ INVALID_STRING; tag_ohb: 97
}
