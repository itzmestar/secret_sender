# secret_sender
Program implements the following command-line interface: ./secret_sender [ip_address] [interface] [type] [message]
program send the [message], encoded as described below, to the IP address specified by [ip_address] on physical interface. [type] specifies the type of packet that the IP datagram will hold, it can be one of: • 0: ICMP Echo Request Message • 1: TCP SYN packet to port 80

Each byte of the message are sent in the IP layer of a packet (so one packet is sent for every byte of the message). The message byte is encoded in the high 8 bits of the Identification field of the IP datagram. The lower 8 bits of the Identification field stay consistent, as they serve as the identifier of this message (and not all 1s, as noted below). The byte number (the number of the byte from the message being sent) is encoded into the lower 8 bits of the Fragment Offset field (note this means that at most we can send 28 -1 size messages). Finally, when there are no more bytes to send, the highest bit of the Fragment Offset is set to 1 and the lower 8 bits of the Fragment Offset field is set to the length of the message (total bytes sent).

program uses the java pcap4j library to create & send ICMP/TCP packets.

Tested to work with: java7

How to run:

./packet_sender [ip_address] [interface] [type] [message]

Where:

ip_address : Destination IP address

interface : Source ethernet interface

type : 0 -> ICMP Echo Request Message Or 1 -> TCP SYN packet to port 80

message : message to be sent in packet

All of the options are mandotary.
