#@ prototext: protoc
int32Op: 100  #@ int32 = 25
messageOp {  #@ SwissArmyKnife = 31
 int32Op: 200  #@ int32 = 25
 stringOp: "nested"  #@ string = 29
}
messageRp {  #@ repeated SwissArmyKnife = 51
 stringOp: "first nested"  #@ string = 29
 uint32Op: 1  #@ uint32 = 33
}
messageRp {  #@ repeated SwissArmyKnife = 51
 stringOp: "second nested"  #@ string = 29
 uint32Op: 2  #@ uint32 = 33
}
