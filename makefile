# Top level makefile for Perfect

all:
	cd PerfectLib && $(MAKE)
	cd PerfectServer && $(MAKE)

clean:
	cd PerfectLib && $(MAKE) clean
	cd PerfectServer && $(MAKE) clean