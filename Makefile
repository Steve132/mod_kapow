all: mod_kapow

mod_kapow: mod_kaPoW.c
	apxs -DLOG_DEBUG -i -a -c mod_kaPoW.c issuer.c verifier.c configuration.c

clean:
	\rm -f *.la *.lo *.o *.slo

