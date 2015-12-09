# Top level makefile for Perfect

all:
	cd PerfectLib && $(MAKE)
	cd PerfectServer && $(MAKE)

examples:
	cd Examples && $(MAKE)

clean:
	cd PerfectLib && $(MAKE) clean
	cd PerfectServer && $(MAKE) clean