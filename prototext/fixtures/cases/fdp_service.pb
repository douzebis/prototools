#@ prototext: protoc
name: "test/service.proto"  #@ string = 1
package: "test.service"  #@ string = 2
syntax: "proto3"  #@ string = 12
message_type {  #@ repeated DescriptorProto = 4
 name: "Request"  #@ string = 1
 field {  #@ repeated FieldDescriptorProto = 2
  name: "query"  #@ string = 1
  number: 1  #@ int32 = 3
  type: TYPE_STRING  #@ Type(9) = 5
 }
}
message_type {  #@ repeated DescriptorProto = 4
 name: "Response"  #@ string = 1
 field {  #@ repeated FieldDescriptorProto = 2
  name: "result"  #@ string = 1
  number: 1  #@ int32 = 3
  type: TYPE_STRING  #@ Type(9) = 5
 }
}
service {  #@ repeated ServiceDescriptorProto = 6
 name: "SearchService"  #@ string = 1
 method {  #@ repeated MethodDescriptorProto = 2
  name: "Search"  #@ string = 1
  input_type: "Request"  #@ string = 2
  output_type: "Response"  #@ string = 3
 }
}
