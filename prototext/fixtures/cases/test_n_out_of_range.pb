#@ prototext: protoc
messageRp {  #@ repeated SwissArmyKnife = 51
 421: " 421 is OK"  #@ bytes
 421: " 421 is OK"  #@ bytes
 421: " 421 is OK"  #@ bytes
}
messageRp {  #@ repeated SwissArmyKnife = 51
 268435456: " 1<<29-1 is OK "  #@ bytes
}
messageRp {  #@ repeated SwissArmyKnife = 51
 536870912: " 1<<29 is OOR "  #@ bytes; TAG_OOR
}
messageRp {  #@ repeated SwissArmyKnife = 51
 4294967296: " 1<<32 is OOR"  #@ bytes; tag_ohb: 13; TAG_OOR
}
messageRp {  #@ repeated SwissArmyKnife = 51
 0: " zero is OOR"  #@ bytes; tag_ohb: 13; TAG_OOR
}
messageRp {  #@ repeated SwissArmyKnife = 51
 1: " one is OK"  #@ bytes; tag_ohb: 13
}
messageRp {  #@ repeated SwissArmyKnife = 51
 0: "\202\200\200\200\200\200\200\200\200\020\021 1<<64 is garbage"  #@ INVALID_TAG_TYPE
}
