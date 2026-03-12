#@ prototext: protoc
name: "test/nested_enum.proto"  #@ string = 1
message_type {  #@ repeated DescriptorProto = 4
 name: "Msg"  #@ string = 1
 field {  #@ repeated FieldDescriptorProto = 2
  name: "val"  #@ string = 1
  number: 1  #@ int32 = 3
  label: LABEL_OPTIONAL  #@ Label(1) = 4
  type: TYPE_STRING  #@ Type(9) = 5
 }
}
