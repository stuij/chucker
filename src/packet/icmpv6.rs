// ICMPv6
// RFC 4443
//
//  0                   1                   2                   3
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |     Type      |     Code      |          Checksum             |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |      Internet Header + 64 bits of Original Data Datagram      |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

// ICMPv6 error messages
//   1  Destination Unreachable
//   2  Packet Too Big
//   3  Time Exceeded
//   4  Parameter Problem
// 100  Private experimentation
// 101  Private experimentation
// 127  Reserved for expansion

// ICMPv6 informational messages
// 128  Echo Request
// 129  Echo Reply
// 130  Multicast Listener Query
// 131  Multicast Listener Report
// 132  Multicast Listener Done
// 133  Router Solicitation     (NDP)
// 134  Router Advertisement    (NDP)
// 135  Neighbor Solicitation   (NDP)
// 136  Neighbor Advertisement  (NDP)
// 137  Redirect Message        (NDP)
// 138  Router Renumbering
// 139  ICMP Node Information Query
// 140  ICMP Node Information Response
// 141  Inverse Neighbor Discovery Solicitation Message    (NDP)
// 142  Inverse Neighbor Discovery Advertistement Message  (NDP)
// 143  Version 2 Multicast Listener Report
// 144  Home Agent Address Discovery Request Message
// 145  Home Agent Address Discovery Reply Message
// 146  Mobile Prefix Solicitation
// 147  Mobile Prefix Advertisement
// 148  Certifcation Path Solicitation   (SEND)
// 149  Certifcation Path Advertisement  (SEND)
// 150  used by experimental mobility protocols such as Seamoby
// 151  Multicast Router Advertisement  (MRD)
// 152  Multicast Router Solicitaion    (MRD)
// 153  Multicast Router Termination    (MRD)
// 154  FMIPv6 Messages
// 155  RPL Control Message
// 200  Private experimentation
// 201  Private experimentation
// 255  Reserved for expansion

