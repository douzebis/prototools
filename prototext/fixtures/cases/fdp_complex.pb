#@ prototext: protoc
name: "test/complex.proto"  #@ string = 1
package: "test.complex"  #@ string = 2
syntax: "proto3"  #@ string = 12
message_type {  #@ repeated DescriptorProto = 4
 name: "ComplexMessage"  #@ string = 1
 field {  #@ repeated FieldDescriptorProto = 2
  name: "id"  #@ string = 1
  number: 1  #@ int32 = 3
  type: TYPE_INT32  #@ Type(5) = 5
 }
 field {  #@ repeated FieldDescriptorProto = 2
  name: "name"  #@ string = 1
  number: 2  #@ int32 = 3
  type: TYPE_STRING  #@ Type(9) = 5
 }
}
enum_type {  #@ repeated EnumDescriptorProto = 5
 name: "Status"  #@ string = 1
 value {  #@ repeated EnumValueDescriptorProto = 2
  name: "UNKNOWN"  #@ string = 1
  number: 0  #@ int32 = 2
 }
 value {  #@ repeated EnumValueDescriptorProto = 2
  name: "ACTIVE"  #@ string = 1
  number: 1  #@ int32 = 2
 }
}
