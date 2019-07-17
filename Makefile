all : pcap_test

pcap_test: main.o
	g++ -g -w -o pcap_test main.o -lpcap

main.o:
	g++ -g -w -c -o main.o main.cpp

clean:
	rm -f pcap_test
	rm -f *.o

