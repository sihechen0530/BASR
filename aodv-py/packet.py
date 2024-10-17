from scapy.all import *

class RREQ(Packet):
    name = "RREQ"
    fields_desc = [
        ByteField("Type", 1),
        BitField("Help", 0, 16), 
        ByteField("HopCount", 0),
        IntField("RREQID", 1),
        IPField("DstIP", '127.0.0.1'),
        IntField("DstSeq", 0),
        IPField("OrigIP", '127.0.0.1'),
        IntField("OrigSeq", 0)
    ]


class RREP(Packet):
    name = "RREP"
    fields_desc = [
        ByteField("Type", 2),
        BitField("Help", 0, 16), 
        ByteField("HopCount", 1),
        IPField("DstIP", '127.0.0.1'),
        IntField("DstSeq", 0),
        IPField("OrigIP", '127.0.0.1'),
        IntField("Lifetime", 0)
    ]


class RERR(Packet):
    name = "RERR"
    fields_desc = [
        ByteField("Type", 3),
        BitField("Help", 0, 16), 
        ByteField("DestCount", 1),
        IPField("IP", '127.0.0.1'),
        IntField("Seq", 0),
        IPField("IP2", '127.0.0.1'),
        IntField("Seq2", 0)
    ]

class DATA(Packet):
    name = "Data"
    fields_desc = [
        ByteField("Type", 3),
        BitField("Help", 0, 16),
        ByteField("HopCount", 0),
        IPField("OrigIP", '127.0.0.1'),
        IPField("DstIP", '127.0.0.1'),
        IPField("Hop1", '0.0.0.0'),
        IPField("Hop2", '0.0.0.0'),
        IPField("Hop3", '0.0.0.0'),
        IPField("Hop4", '0.0.0.0'),
        IPField("Hop5", '0.0.0.0'),
        IPField("Hop6", '0.0.0.0'),
        IPField("Hop7", '0.0.0.0'),
        IPField("Hop8", '0.0.0.0'),
        StrField("Data", "")
    ]

