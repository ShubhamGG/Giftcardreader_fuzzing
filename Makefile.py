default: giftcardreader

giftcardreader: giftcardreader.c giftcard.h
	gcc -g -o giftcardreader giftcardreader.c

asan: giftcardreader.c giftcard.h
	gcc -fsanitize=address -g -o giftcardreader giftcardreader.c

test: giftcardreader
	./runtests.sh

fuzzer: giftcardreader.c fuzzer.c
	clang -g -fsanitize=address,fuzzer -D FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION giftcardreader.c fuzzer.c -o fuzzer

# .PHONY tells make to always assume this target needs
# to be rebuilt
.PHONY: clean
clean:
	rm -f *.o giftcardreader fuzzer
