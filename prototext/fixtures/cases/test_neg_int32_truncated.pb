#@ prototext: protoc
int32Rp: -2147483648  #@ repeated int32 = 45; truncated_neg
int32Rp: -2147483648  #@ repeated int32 = 45
int32Rp: -1  #@ repeated int32 = 45; truncated_neg
int32Rp: -1  #@ repeated int32 = 45
enumRp: -2147483648  #@ repeated int32 = 54; truncated_neg
enumRp: -2147483648  #@ repeated int32 = 54
int32Pk: [1, -1, -2147483648, -1, 2]  #@ repeated int32 [packed=true] = 85; packed_truncated_neg: [0, 1, 1, 0, 0]
enumPk: [3, -1, -2147483648, -2147483648]  #@ repeated int32 [packed=true] = 94; packed_truncated_neg: [0, 1, 0, 1]
