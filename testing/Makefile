.PHONY : build clean check_alignments

.DEFAULT_GOAL := build

wasiclang_SOURCE_DIR=/home/shr/Code/LibrarySandboxing/rlbox_lucet_sandbox/build/_deps/wasiclang-src

out:
	mkdir -p out

out/test.wasm: test.cpp
	$(wasiclang_SOURCE_DIR)/opt/wasi-sdk/bin/clang++ --sysroot $(wasiclang_SOURCE_DIR)/opt/wasi-sdk/share/wasi-sysroot/ -Wl,--export-all -O3 $< -o $@

out/test.wat: out/test.wasm
	/home/shr/Code/wabt/bin/wasm2wat $< > $@

out/test.o: out/test.wasm /home/shr/Code/lucet-spectre/target/debug/lucetc
	/home/shr/Code/lucet-spectre/target/debug/lucetc \
		--bindings /home/shr/Code/lucet-spectre/lucet-wasi/bindings.json \
		--guard-size "4GiB" \
		--min-reserved-size "4GiB" \
		--max-reserved-size "4GiB" \
		--emit obj \
		out/test.wasm -o $@

out/test.so: out/test.wasm /home/shr/Code/lucet-spectre/target/debug/lucetc
	/home/shr/Code/lucet-spectre/target/debug/lucetc \
		--bindings /home/shr/Code/lucet-spectre/lucet-wasi/bindings.json \
		--guard-size "4GiB" \
		--min-reserved-size "4GiB" \
		--max-reserved-size "4GiB" \
		out/test.wasm -o $@

out/test.asm: out/test.o
	objdump -d out/test.o $< > $@

out/test_so.asm: out/test.so
	objdump -d out/test.o $< > $@

out/test_align.o: out/test.wasm /home/shr/Code/lucet-spectre/target/debug/lucetc
	/home/shr/Code/lucet-spectre/target/debug/lucetc \
		--bindings /home/shr/Code/lucet-spectre/lucet-wasi/bindings.json \
		--guard-size "4GiB" \
		--min-reserved-size "4GiB" \
		--max-reserved-size "4GiB" \
		--emit obj \
		--enable-spectre-guards \
		--spectre-branch-alignment "31" \
		--spectre-branch-alignment-block "32" \
		out/test.wasm -o $@

out/test_align.so: out/test.wasm /home/shr/Code/lucet-spectre/target/debug/lucetc
	/home/shr/Code/lucet-spectre/target/debug/lucetc \
		--bindings /home/shr/Code/lucet-spectre/lucet-wasi/bindings.json \
		--guard-size "4GiB" \
		--min-reserved-size "4GiB" \
		--max-reserved-size "4GiB" \
		--enable-spectre-guards \
		--spectre-branch-alignment "31" \
		--spectre-branch-alignment-block "32" \
		out/test.wasm -o $@

out/test_align.asm: out/test_align.o
	objdump -d out/test_align.o $< > $@

out/test_align_so.asm: out/test_align.so
	objdump -d out/test_align.o $< > $@

check_alignments: out/test_align.asm
	./check_alignments.py $< --func "guest_func_*" --limit 10 --loginfo False

build: out out/test.wasm out/test.wat out/test.o out/test.so out/test.asm out/test_so.asm out/test_align.o out/test_align.so out/test_align.asm out/test_align_so.asm check_alignments

clean:
	rm -rf out