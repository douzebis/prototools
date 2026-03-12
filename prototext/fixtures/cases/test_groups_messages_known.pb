#@ prototext: protoc
int32Op: 7  #@ int32 = 25
GroupOp {  #@ group; GroupOp = 30
 uint64Op: 42  #@ uint64 = 130
 messageOp {  #@ SwissArmyKnife = 131
  stringOp: "inside groupop"  #@ string = 29
 }
}
messageOp {  #@ SwissArmyKnife = 31
 int32Op: 11  #@ int32 = 25
 GroupOp {  #@ group; GroupOp = 30
  uint64Op: 99  #@ uint64 = 130
 }
}
GroupRp {  #@ group; repeated GroupRp = 50
 uint64Op: 1  #@ uint64 = 150
 messageOp {  #@ SwissArmyKnife = 151
  stringOp: "first grouprp"  #@ string = 29
 }
}
GroupRp {  #@ group; repeated GroupRp = 50
 uint64Op: 2  #@ uint64 = 150
}
messageRp {  #@ repeated SwissArmyKnife = 51
 uint32Op: 100  #@ uint32 = 33
 GroupOp {  #@ group; GroupOp = 30
  uint64Op: 77  #@ uint64 = 130
 }
}
messageRp {  #@ repeated SwissArmyKnife = 51
 stringOp: "second messagerp"  #@ string = 29
}
