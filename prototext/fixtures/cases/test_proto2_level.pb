#@ prototext: protoc
uint64Rp: 0  #@ repeated uint64 = 44
fixed64Rp: 0  #@ repeated fixed64 = 46
bytesRp: ""  #@ repeated bytes = 52
4 {  #@ group
 11: 0  #@ varint
}
GROUP {  #@ group; GROUP = 13
 nested {  #@ SwissArmyKnife = 113
  fixed64Rp: 0  #@ repeated fixed64 = 46
  bytesRp: ""  #@ repeated bytes = 52
  uint32Rp: 0  #@ repeated uint32 = 53
 }
}
uint32Rp: 0  #@ repeated uint32 = 53
