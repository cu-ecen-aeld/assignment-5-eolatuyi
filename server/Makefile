# e.g 
#		Clean              : make clean
#		Native Build 	   : make
#		CROSS Compile Build: make CROSS_COMPILE=aarch64-none-linux-gnu-	
# Author: Ebenezer Olatuyi
# Date  :5-14-2024
CC := gcc
CFLAGS := -Wall -Wextra -Werror -pthread

ifeq ($(CROSS_COMPILE),aarch64-none-linux-gnu-)
	CC := $(CROSS_COMPILE)gcc
endif

.PHONY: all clean

all: aesdsocket

aesdsocket: aesdsocket.o
	$(CC) $(CFLAGS) -o $@ $^

aesdsocket.o: aesdsocket.c
	$(CC) $(CFLAGS) -c $<

clean:
	rm -f aesdsocket aesdsocket.o
