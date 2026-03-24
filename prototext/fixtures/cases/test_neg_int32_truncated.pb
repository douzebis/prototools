#@ prototext: protoc
int32Rp: -2147483648  #@ repeated int32 = 45; truncated_neg
int32Rp: -2147483648  #@ repeated int32 = 45
int32Rp: -1  #@ repeated int32 = 45; truncated_neg
int32Rp: -1  #@ repeated int32 = 45
enumRp: -2147483648  #@ repeated int32 = 54; truncated_neg
enumRp: -2147483648  #@ repeated int32 = 54
int32Pk: 1  #@ repeated int32 [packed=true] = 85; pack_size: 5
int32Pk: -1  #@ repeated int32 [packed=true] = 85; neg
int32Pk: -2147483648  #@ repeated int32 [packed=true] = 85; neg
int32Pk: -1  #@ repeated int32 [packed=true] = 85
int32Pk: 2  #@ repeated int32 [packed=true] = 85
enumPk: 3  #@ repeated int32 [packed=true] = 94; pack_size: 4
enumPk: -1  #@ repeated int32 [packed=true] = 94; neg
enumPk: -2147483648  #@ repeated int32 [packed=true] = 94
enumPk: -2147483648  #@ repeated int32 [packed=true] = 94; neg
