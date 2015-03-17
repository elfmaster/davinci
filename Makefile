all: stub davinci stripx gen_shellcode
stub:
	gcc -static stub.c -o stub
davinci:
	gcc davinci.c -o davinci
stripx:
	gcc utils/stripx.c -o utils/stripx
gen_shellcode:
	gcc utils/gen_shellcode.c -o utils/gen_shellcode
clean:
	rm -f stub davinci utils/gen_shellcode utils/stripx
