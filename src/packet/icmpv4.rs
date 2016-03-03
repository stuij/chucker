use super::pkt;

// ICMP
// RFC 792
//
//  0                   1                   2                   3
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |     Type      |     Code      |          Checksum             |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                             unused                            |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |      Internet Header + 64 bits of Original Data Datagram      |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
// type / code
//  0 = Echo reply
//  3 = Destination unreachable
//      Code
//       0	Net unreachable
//       1	Host unreachable
//       2	Protocol unreachable
//       3	Port unreachable
//       4	Fragmentation needed but DF set
//       5	Source route failed
//       6	Destination network unknown
//       7	Destination host unknown
//       8	Source host isolated
//       9	Network administratively prohibited
//      10	Host administratively prohibited
//      11	Network unreachable for requested TOS
//      12	Host unreachable for requested TOS
//      13	Communication administratively prohibited
//  4 = Source quench
//  5 = Redirect
//      Code
//       0	Redirect datagram for the network
//       1	Redirect datagram for the host
//       2	Redirect datagram for the TOS and network
//       3	Redirect datagram for the TOS and host
//  8 = Echo request
//  9 = Router advertisement
// 10 = Router selection
// 11 = Time exceeded
//      Code
//       0	Time to live exceeded in transit
//       1	Fragment reassembly time exceeded
// 12 = Parameter problem
//      Code
//       0	Pointer indicates the error
//       1	Missing a required option
//       2	Bad length
// 13 = Timestamp
// 14 = Timestamp reply
// 15 = Information request
// 16 = Information reply
// 17 = Address mask request
// 18 = Address mask reply
// 30 = Traceroute (probably just Microsoft hosts, traceroute
//      should be done via UDP)
