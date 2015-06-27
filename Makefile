
all: rawsend udp2txt mirror_udp

udp2txt: udp2txt.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ $^ -lpcap

rawsend: rawsend.c

mirror_udp: mirror_udp.c

clean:
	@rm -rf rawsend udp2txt mirror_udp
