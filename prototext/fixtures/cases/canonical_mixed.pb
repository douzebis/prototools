#@ prototext: protoc
int64Op: 9999  #@ int64 = 23
stringOp: "test"  #@ string = 29
messageOp {  #@ SwissArmyKnife = 31
 doubleOp: 1.23e-10  #@ double = 21
 boolOp: false  #@ bool = 28
}
bytesOp: "data"  #@ bytes = 32
floatRp: 1  #@ repeated float = 42
floatRp: 2  #@ repeated float = 42
