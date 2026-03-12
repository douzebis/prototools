#@ prototext: protoc
uint64Rp: 12345  #@ repeated uint64 = 44
stringRp: "Complex MPM test message"  #@ repeated string = 49
floatRp: 3.14159  #@ repeated float = 42
boolRp: true  #@ repeated bool = 48
bytesRp: "Binary data for MPM testing"  #@ repeated bytes = 52
messageRp {  #@ repeated SwissArmyKnife = 51
 uint32Rp: 42  #@ repeated uint32 = 53
 stringRp: "Nested message in MPM"  #@ repeated string = 49
 10 {  #@ group
  1: 999  #@ varint
  2: "Group inside nested message"  #@ bytes
 }
}
