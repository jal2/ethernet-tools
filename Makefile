
all: rawsend udp2txt

udp2txt: udp2txt.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ $^ -lpcap

rawsend: rawsend.c

clean:
	@rm -rf rawsend udp2txt
