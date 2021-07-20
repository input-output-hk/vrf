ifeq ($(shell uname),Darwin)
	    LDFLAGS := -Wl,-dead_strip -lsodium
    else
	    LDFLAGS := -Wl,--gc-sections -lpthread -ldl -lsodium

    endif

test:
	$(CC) $(LDFLAGS)  tests/vrf_libsodium.c -o tests/vrf_libsodium
	cargo test check_output -- --nocapture
	tests/vrf_libsodium

clean:
		rm -rf tests/vrf_libsodium
