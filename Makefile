CC = g++
CFLAGS=-g -Wall -Werror 
TARGET=proj4

all: $(TARGET).cpp
	$(CC) -std=c++11 $(TARGET).cpp $(CFLAGS) -o $(TARGET)
clean:
	rm -f $(TARGET) 
	rm -rf *.dSYM
	rm -rf *.out

distclean: clean