ethernet-tools
==============

a set of small commandline ethernet tools for Linux.

Call
```
	make
```
to build them.


rawsend
-------

This tool lets you send arbitrary ethernet frames from command line under Linux.

```
./rawsend <options> [<byte0> <byte1> ...]

Options:
-w <ms>      - wait for ms milliseconds after sending a packet (default: 100)
-v           - verbose output
-o           - use own mac address as SA (default: no)
-t <n>       - set socket tx buffer size
-c <offset>  - counting mode: increment byte at offset (from DA) by one in each msg
-n <n>       - send a number of msgs (default: 1) - zero for an infinite number
-i <interf>  - use this net device (default: eth0)
-s <src_mac>
-d <dst_mac> - source, destination MAC address (default: taken from payload)

<byteX>      - payload
```

Example:
```
./rawsend -o -d 00:11:22:33:44:55 -i eth4 -n 0 8 6 1 2 3 4 5

-o use the source MAC address from the interface given with -i
-d 00:11:22:33:44:55  the destination MAC address
-i eth4  the interface
-n 0  number of packets to send (0 == infinite)
8 6 1 2 3 4 5  the payload after the source MAC address in the packet
```
If you provide any data on stdin, these bytes are appended to the payload given on the command line.

udp2txt
-------

This tool will extract UDP packets with a given destination port from a pcap file (e.g. the saved file from a tcpdump)
and print the payload preceeded by a timestamp (absolute time in UTC).
This may be quite helpful when programs send their printable output via UDP and we want to timestamp the lines. 

You need to install the package libpcap-dev in order to build this program.

Example:
```
./udp2txt 6500 example1.pcap
```

mirror_udp
----------

This program mirrors multicase UDP packet back to the sender. It shall be used for loopback tests; it is still work in progress.