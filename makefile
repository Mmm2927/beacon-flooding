LDLIBS += -lpcap

all: beacon-flooding

beacon-flooding: beacon-flooding.cpp

clean:
	rm -f beacon-flooding *.o
