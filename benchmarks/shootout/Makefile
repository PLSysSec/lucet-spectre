LUCET_ROOT:=$(abspath ../..)

WASI_SDK?=/opt/wasi-sdk
WASI_CC?=$(WASI_SDK)/bin/clang
BINARYEN_DIR?=/opt/binaryen
WASM_OPT?=$(shell command -v wasm-opt || echo $(BINARYEN_DIR)/bin/wasm-opt)

LUCETC:=$(LUCET_ROOT)/target/release/lucetc

LUCET_RUNTIME:=$(LUCET_ROOT)/lucet-runtime
LUCET_WASI:=$(LUCET_ROOT)/lucet-wasi
SIGHTGLASS:=$(LUCET_ROOT)/sightglass


SHOOTOUT:=$(LUCET_ROOT)/sightglass/benchmarks/shootout
SHOOTOUT_SRCS:=$(shell ls $(SHOOTOUT)/*.c)
SHOOTOUT_NATIVE_OBJS:=
SHOOTOUT_LUCET_OBJS:=

LUCET_BIN=$(LUCET_ROOT)/target/release

# Note this makefile uses the CET binaries only if REALLY_USE_CET is defined
ifdef REALLY_USE_CET
	CET_CFLAGS:=-fcf-protection=full
	CET_LINKERFLAGS:=-Wl,-z,ibt -Wl,-z,shstk
	CET_LUCET_BIN:=$(LUCET_ROOT)/target-cet/release
else
	CET_CFLAGS:=
	CET_LINKERFLAGS:=
	CET_LUCET_BIN:=$(LUCET_BIN)
endif

LUCETC_FLAGS:=--opt-level speed_and_size --min-reserved-size 4294967296
COMMON_CFLAGS:=--std=c99 -Ofast -Wall -W -Wno-implicit-fallthrough -I$(SIGHTGLASS)/include
UNROLL_FLAGS=-funroll-loops -mllvm --unroll-runtime -mllvm --unroll-runtime-epilog

LOADLFENCE_FLAGS:=--spectre-mitigation=loadlfence
STRAWMAN_FLAGS:=--spectre-mitigation=strawman
SFI_FULL_FLAGS:=--spectre-mitigation=sfi
CET_FULL_FLAGS:=--spectre-mitigation=cet
SFI_ASLR_FLAGS:=--spectre-mitigation=sfiaslr
CET_ASLR_FLAGS:=--spectre-mitigation=cetaslr
BLADE_FLAGS:=--spectre-pht-mitigation=blade
PHTTOBTB_FLAGS:=--spectre-pht-mitigation=phttobtb
INTERLOCK_FLAGS:=--spectre-pht-mitigation=interlock


SHOOTOUT_NATIVE_CFLAGS:=-march=native -fPIC \
	-DIMPL_REFERENCE -DUSE_LEND \
	-Dmalloc=lend_malloc -Dcalloc=lend_calloc -Dfree=lend_free

BINARYEN_VERSION=86

TIMESTAMP:=$(shell date --iso=seconds)

ifdef CI
	SIGHTGLASS_ARGS:=--quick
endif

default: build

.PHONY: bench
bench: run

.PHONY: run

run:
	-rm -rf /tmp/sightglass_results.csv
	-rm -rf $(LUCET_ROOT)/../benchmarks/current_sightglass
	mkdir -p $(LUCET_ROOT)/../benchmarks/current_sightglass/baseline
	mkdir -p $(LUCET_ROOT)/../benchmarks/current_sightglass/ours
	mkdir -p $(LUCET_ROOT)/../benchmarks/current_sightglass/ours_expensive

	$(LUCET_BIN)/sightglass -c reference.toml $(SIGHTGLASS_ARGS)
	cp /tmp/sightglass_results.csv $(LUCET_ROOT)/../benchmarks/current_sightglass/baseline/reference-latest.csv
	cp /tmp/sightglass_results.csv $(LUCET_ROOT)/../benchmarks/current_sightglass/ours/reference-latest.csv
	cp /tmp/sightglass_results.csv $(LUCET_ROOT)/../benchmarks/current_sightglass/ours_expensive/reference-latest.csv
	rm /tmp/sightglass_results.csv

	$(LUCET_BIN)/sightglass -c baseline.toml $(SIGHTGLASS_ARGS)
	mv /tmp/sightglass_results.csv $(LUCET_ROOT)/../benchmarks/current_sightglass/baseline/baseline-latest.csv

	$(LUCET_BIN)/sightglass -c reference_unrolled.toml $(SIGHTGLASS_ARGS)
	mv /tmp/sightglass_results.csv $(LUCET_ROOT)/../benchmarks/current_sightglass/ours/reference_unrolled-latest.csv

	$(LUCET_BIN)/sightglass -c sfi_aslr.toml $(SIGHTGLASS_ARGS)
	mv /tmp/sightglass_results.csv $(LUCET_ROOT)/../benchmarks/current_sightglass/ours/sfi_aslr-latest.csv

	$(CET_LUCET_BIN)/sightglass -c cet_aslr.toml $(SIGHTGLASS_ARGS)
	mv /tmp/sightglass_results.csv $(LUCET_ROOT)/../benchmarks/current_sightglass/ours/cet_aslr-latest.csv

	$(LUCET_BIN)/sightglass -c sfi_full.toml $(SIGHTGLASS_ARGS)
	mv /tmp/sightglass_results.csv $(LUCET_ROOT)/../benchmarks/current_sightglass/ours/sfi_full-latest.csv

	$(CET_LUCET_BIN)/sightglass -c cet_full.toml $(SIGHTGLASS_ARGS)
	mv /tmp/sightglass_results.csv $(LUCET_ROOT)/../benchmarks/current_sightglass/ours/cet_full-latest.csv

	$(LUCET_BIN)/sightglass -c expensive.toml $(SIGHTGLASS_ARGS)
	mv /tmp/sightglass_results.csv $(LUCET_ROOT)/../benchmarks/current_sightglass/ours_expensive/expensive.csv

	python3 $(LUCET_ROOT)/../sfi-spectre-testing/scripts/graph_sightglass.py \
		$(LUCET_ROOT)/../benchmarks/current_sightglass/baseline/reference-latest.csv \
		$(LUCET_ROOT)/../benchmarks/current_sightglass/baseline/baseline-latest.csv

	python3 $(LUCET_ROOT)/../sfi-spectre-testing/scripts/graph_sightglass.py --usePercent \
		$(LUCET_ROOT)/../benchmarks/current_sightglass/ours/reference-latest.csv \
		$(LUCET_ROOT)/../benchmarks/current_sightglass/ours/reference_unrolled-latest.csv \
		$(LUCET_ROOT)/../benchmarks/current_sightglass/ours/sfi_aslr-latest.csv \
		$(LUCET_ROOT)/../benchmarks/current_sightglass/ours/cet_aslr-latest.csv \
		$(LUCET_ROOT)/../benchmarks/current_sightglass/ours/sfi_full-latest.csv \
		$(LUCET_ROOT)/../benchmarks/current_sightglass/ours/cet_full-latest.csv

	python3 $(LUCET_ROOT)/../sfi-spectre-testing/scripts/graph_sightglass.py --usePercent \
		$(LUCET_ROOT)/../benchmarks/current_sightglass/ours_expensive/reference-latest.csv \
		$(LUCET_ROOT)/../benchmarks/current_sightglass/ours_expensive/expensive.csv

	mv $(LUCET_ROOT)/../benchmarks/current_sightglass $(LUCET_ROOT)/../benchmarks/sightglass_$(shell date --iso=seconds)

run_pht:
	-rm -rf $(LUCET_ROOT)/../benchmarks/current_sightglass_pht
	mkdir $(LUCET_ROOT)/../benchmarks/current_sightglass_pht

	$(LUCET_BIN)/sightglass -c pht.toml $(SIGHTGLASS_ARGS)
	mv /tmp/sightglass_results.csv $(LUCET_ROOT)/../benchmarks/current_sightglass_pht/sightglass_results.csv

	python3 $(LUCET_ROOT)/../sfi-spectre-testing/scripts/graph_sightglass.py $(LUCET_ROOT)/../benchmarks/current_sightglass_pht/sightglass_results.csv
	mv $(LUCET_ROOT)/../benchmarks/current_sightglass_pht $(LUCET_ROOT)/../benchmarks/sightglass_pht_$(shell date --iso=seconds)


.PHONY: build
build: $(LUCETC)
build: build/native/implementation.so

build: build/lucet/implementation.so
build: build/lucet/module.so

build: build/lucet_unroll/implementation.so
build: build/lucet_unroll/module.so

build: build/loadlfence/implementation.so
build: build/loadlfence/module.so

build: build/strawman/implementation.so
build: build/strawman/module.so

build: build/sfi_full/implementation.so
build: build/sfi_full/module.so

build: build/cet_full/implementation.so
build: build/cet_full/module.so

build: build/sfi_aslr/implementation.so
build: build/sfi_aslr/module.so

build: build/cet_aslr/implementation.so
build: build/cet_aslr/module.so

build: build/blade/implementation.so
build: build/blade/module.so

build: build/phttobtb/implementation.so
build: build/phttobtb/module.so

build: build/interlock/implementation.so
build: build/interlock/module.so

build: $(LUCET_BIN)/sightglass

# With the xenial gcc (5.4.0) this pins the CPU for minutes if above -O1, so its getting downgraded to -O1
build/native/shootout/switch2.o: $(SHOOTOUT)/switch2.c
	@mkdir -p $(@D)
	$(CC) $(SHOOTOUT_NATIVE_CFLAGS) $(COMMON_CFLAGS) -O1 -c $^ -o $@

build/native/shootout/%.o: $(SHOOTOUT)/%.c
	@mkdir -p $(@D)
	$(CC) $(SHOOTOUT_NATIVE_CFLAGS) $(COMMON_CFLAGS) -c $^ -o $@

build/native/implementation.so: $(patsubst %.c, %.o, $(addprefix build/native/shootout/, $(notdir $(SHOOTOUT_SRCS))))
	@mkdir -p $(@D)
	$(CC) -shared -o $@ $^

build/lucet/shootout/%.o: $(SHOOTOUT)/%.c
	@mkdir -p $(@D)
	$(WASI_CC) $(COMMON_CFLAGS) -c $^ -o $@

build/lucet/module.wasm.unoptimized: $(patsubst %.c, %.o, $(addprefix build/lucet/shootout/, $(notdir $(SHOOTOUT_SRCS))))
	@mkdir -p $(@D)
	$(WASI_CC) $^ -o $@ -nostartfiles -Wl,--no-entry -Wl,--export-all

build/lucet/module.wasm: build/lucet/module.wasm.unoptimized
	$(WASM_OPT) -mvp --disable-mutable-globals -O4 -o $@ $^

build/lucet/module.clif: build/lucet/module.wasm
	@mkdir -p $(@D)
	$(LUCETC) $(LUCETC_FLAGS) --emit=clif \
		--bindings=bindings.json \
		--bindings=$(LUCET_WASI)/bindings.json \
		$< -o $@

build/lucet_unroll/shootout/%.o: $(SHOOTOUT)/%.c
	@mkdir -p $(@D)
	$(WASI_CC) $(COMMON_CFLAGS) $(UNROLL_FLAGS) -c $^ -o $@

build/lucet_unroll/module.wasm.unoptimized: $(patsubst %.c, %.o, $(addprefix build/lucet_unroll/shootout/, $(notdir $(SHOOTOUT_SRCS))))
	@mkdir -p $(@D)
	$(WASI_CC) $^ -o $@ -nostartfiles -Wl,--no-entry -Wl,--export-all

build/lucet_unroll/module.wasm: build/lucet_unroll/module.wasm.unoptimized
	$(WASM_OPT) -mvp --disable-mutable-globals -O4 -o $@ $^

build/lucet_unroll/module.clif: build/lucet_unroll/module.wasm
	@mkdir -p $(@D)
	$(LUCETC) $(LUCETC_FLAGS) --emit=clif \
		--bindings=bindings.json \
		--bindings=$(LUCET_WASI)/bindings.json \
		$< -o $@

build/lucet/%.o: %.c
	@mkdir -p $(@D)
	$(CC) --std=c99 -fPIC -D_GNU_SOURCE -g3 $(COMMON_CFLAGS) \
		-fvisibility=default \
		-I$(LUCET_RUNTIME)/include \
		-I$(LUCET_WASI)/include \
		-DWASM_MODULE=$(abspath build/lucet/module.so) \
		-c $^ -o $@
build/lucet_unroll/%.o: %.c
	@mkdir -p $(@D)
	$(CC) --std=c99 -fPIC -D_GNU_SOURCE -g3 $(COMMON_CFLAGS) \
		-fvisibility=default \
		-I$(LUCET_RUNTIME)/include \
		-I$(LUCET_WASI)/include \
		-DWASM_MODULE=$(abspath build/lucet/module.so) \
		-c $^ -o $@
build/loadlfence/%.o: %.c
	@mkdir -p $(@D)
	$(CC) --std=c99 -fPIC -D_GNU_SOURCE -g3 $(COMMON_CFLAGS) \
		-fvisibility=default \
		-I$(LUCET_RUNTIME)/include \
		-I$(LUCET_WASI)/include \
		-DWASM_MODULE=$(abspath build/loadlfence/module.so) \
		-c $^ -o $@
build/strawman/%.o: %.c
	@mkdir -p $(@D)
	$(CC) --std=c99 -fPIC -D_GNU_SOURCE -g3 $(COMMON_CFLAGS) \
		-fvisibility=default \
		-I$(LUCET_RUNTIME)/include \
		-I$(LUCET_WASI)/include \
		-DWASM_MODULE=$(abspath build/strawman/module.so) \
		-c $^ -o $@
build/sfi_full/%.o: %.c
	@mkdir -p $(@D)
	$(CC) --std=c99 -fPIC -D_GNU_SOURCE -g3 $(COMMON_CFLAGS) \
		-fvisibility=default \
		-I$(LUCET_RUNTIME)/include \
		-I$(LUCET_WASI)/include \
		-DWASM_MODULE=$(abspath build/sfi_full/module.so) \
		-c $^ -o $@
build/cet_full/%.o: %.c
	@mkdir -p $(@D)
	$(CC) --std=c99 -fPIC -D_GNU_SOURCE -g3 $(COMMON_CFLAGS) $(CET_CFLAGS) \
		-fvisibility=default \
		-I$(LUCET_RUNTIME)/include \
		-I$(LUCET_WASI)/include \
		-DWASM_MODULE=$(abspath build/cet_full/module.so) \
		-DUSE_MPK=1 \
		-c $^ -o $@
build/sfi_aslr/%.o: %.c
	@mkdir -p $(@D)
	$(CC) --std=c99 -fPIC -D_GNU_SOURCE -g3 $(COMMON_CFLAGS) \
		-fvisibility=default \
		-I$(LUCET_RUNTIME)/include \
		-I$(LUCET_WASI)/include \
		-DWASM_MODULE=$(abspath build/sfi_aslr/module.so) \
		-c $^ -o $@
build/cet_aslr/%.o: %.c
	@mkdir -p $(@D)
	$(CC) --std=c99 -fPIC -D_GNU_SOURCE -g3 $(COMMON_CFLAGS) $(CET_CFLAGS) \
		-fvisibility=default \
		-I$(LUCET_RUNTIME)/include \
		-I$(LUCET_WASI)/include \
		-DWASM_MODULE=$(abspath build/cet_aslr/module.so) \
		-DUSE_MPK=1 \
		-c $^ -o $@
build/blade/%.o: %.c
	@mkdir -p $(@D)
	$(CC) --std=c99 -fPIC -D_GNU_SOURCE -g3 $(COMMON_CFLAGS) \
		-fvisibility=default \
		-I$(LUCET_RUNTIME)/include \
		-I$(LUCET_WASI)/include \
		-DWASM_MODULE=$(abspath build/blade/module.so) \
		-c $^ -o $@
build/phttobtb/%.o: %.c
	@mkdir -p $(@D)
	$(CC) --std=c99 -fPIC -D_GNU_SOURCE -g3 $(COMMON_CFLAGS) \
		-fvisibility=default \
		-I$(LUCET_RUNTIME)/include \
		-I$(LUCET_WASI)/include \
		-DWASM_MODULE=$(abspath build/phttobtb/module.so) \
		-c $^ -o $@
build/interlock/%.o: %.c
	@mkdir -p $(@D)
	$(CC) --std=c99 -fPIC -D_GNU_SOURCE -g3 $(COMMON_CFLAGS) \
		-fvisibility=default \
		-I$(LUCET_RUNTIME)/include \
		-I$(LUCET_WASI)/include \
		-DWASM_MODULE=$(abspath build/interlock/module.so) \
		-c $^ -o $@

build/lucet/implementation.so: $(LUCET_BIN)/liblucet_unified.a
build/lucet/implementation.so: build/lucet/wrapper.o
build/lucet/implementation.so: build/lucet/hostcalls.o
	@mkdir -p $(@D)
	$(CXX) -rdynamic -shared \
		build/lucet/wrapper.o build/lucet/hostcalls.o \
		-L $(LUCET_BIN) \
		-Wl,-rpath $(LUCET_BIN) \
		 -Wl,--whole-archive -l:liblucet_unified.a  -Wl,--no-whole-archive -ldl -lrt -o $@

build/lucet_unroll/implementation.so: $(LUCET_BIN)/liblucet_unified.a
build/lucet_unroll/implementation.so: build/lucet_unroll/wrapper.o
build/lucet_unroll/implementation.so: build/lucet_unroll/hostcalls.o
	@mkdir -p $(@D)
	$(CXX) -rdynamic -shared \
		build/lucet_unroll/wrapper.o build/lucet_unroll/hostcalls.o \
		-L $(LUCET_BIN) \
		-Wl,-rpath $(LUCET_BIN) \
		 -Wl,--whole-archive -l:liblucet_unified.a  -Wl,--no-whole-archive -ldl -lrt -o $@

build/loadlfence/implementation.so: $(LUCET_BIN)/liblucet_unified.a
build/loadlfence/implementation.so: build/loadlfence/wrapper.o
build/loadlfence/implementation.so: build/loadlfence/hostcalls.o
	@mkdir -p $(@D)
	$(CXX) -rdynamic -shared \
		build/loadlfence/wrapper.o build/loadlfence/hostcalls.o \
		-L $(LUCET_BIN) \
		-Wl,-rpath $(LUCET_BIN) \
		 -Wl,--whole-archive -l:liblucet_unified.a  -Wl,--no-whole-archive -ldl -lrt -o $@

build/strawman/implementation.so: $(LUCET_BIN)/liblucet_unified.a
build/strawman/implementation.so: build/strawman/wrapper.o
build/strawman/implementation.so: build/strawman/hostcalls.o
	@mkdir -p $(@D)
	$(CXX) -rdynamic -shared \
		build/strawman/wrapper.o build/strawman/hostcalls.o \
		-L $(LUCET_BIN) \
		-Wl,-rpath $(LUCET_BIN) \
		 -Wl,--whole-archive -l:liblucet_unified.a  -Wl,--no-whole-archive -ldl -lrt -o $@

build/sfi_full/implementation.so: $(LUCET_BIN)/liblucet_unified.a
build/sfi_full/implementation.so: build/sfi_full/wrapper.o
build/sfi_full/implementation.so: build/sfi_full/hostcalls.o
	@mkdir -p $(@D)
	$(CXX) -rdynamic -shared \
		build/sfi_full/wrapper.o build/sfi_full/hostcalls.o \
		-L $(LUCET_BIN) \
		-Wl,-rpath $(LUCET_BIN) \
		 -Wl,--whole-archive -l:liblucet_unified.a  -Wl,--no-whole-archive -ldl -lrt -o $@

build/cet_full/implementation.so: $(LUCET_BIN)/liblucet_unified.a
build/cet_full/implementation.so: build/cet_full/wrapper.o
build/cet_full/implementation.so: build/cet_full/hostcalls.o
	@mkdir -p $(@D)
	$(CXX) -rdynamic -shared $(CET_CFLAGS) $(CET_LINKERFLAGS) \
		build/cet_full/wrapper.o build/cet_full/hostcalls.o \
		-L $(CET_LUCET_BIN) \
		-Wl,-rpath $(CET_LUCET_BIN) \
		 -Wl,--whole-archive -l:liblucet_unified.a  -Wl,--no-whole-archive -ldl -lrt -o $@

build/sfi_aslr/implementation.so: $(LUCET_BIN)/liblucet_unified.a
build/sfi_aslr/implementation.so: build/sfi_aslr/wrapper.o
build/sfi_aslr/implementation.so: build/sfi_aslr/hostcalls.o
	@mkdir -p $(@D)
	$(CXX) -rdynamic -shared \
		build/sfi_aslr/wrapper.o build/sfi_aslr/hostcalls.o \
		-L $(LUCET_BIN) \
		-Wl,-rpath $(LUCET_BIN) \
		 -Wl,--whole-archive -l:liblucet_unified.a  -Wl,--no-whole-archive -ldl -lrt -o $@

build/cet_aslr/implementation.so: $(LUCET_BIN)/liblucet_unified.a
build/cet_aslr/implementation.so: build/cet_aslr/wrapper.o
build/cet_aslr/implementation.so: build/cet_aslr/hostcalls.o
	@mkdir -p $(@D)
	$(CXX) -rdynamic -shared $(CET_CFLAGS) $(CET_LINKERFLAGS) \
		build/cet_aslr/wrapper.o build/cet_aslr/hostcalls.o \
		-L $(CET_LUCET_BIN) \
		-Wl,-rpath $(CET_LUCET_BIN) \
		 -Wl,--whole-archive -l:liblucet_unified.a  -Wl,--no-whole-archive -ldl -lrt -o $@

build/blade/implementation.so: $(LUCET_BIN)/liblucet_unified.a
build/blade/implementation.so: build/blade/wrapper.o
build/blade/implementation.so: build/blade/hostcalls.o
	@mkdir -p $(@D)
	$(CXX) -rdynamic -shared \
		build/blade/wrapper.o build/blade/hostcalls.o \
		-L $(LUCET_BIN) \
		-Wl,-rpath $(LUCET_BIN) \
		 -Wl,--whole-archive -l:liblucet_unified.a  -Wl,--no-whole-archive -ldl -lrt -o $@

build/phttobtb/implementation.so: $(LUCET_BIN)/liblucet_unified.a
build/phttobtb/implementation.so: build/phttobtb/wrapper.o
build/phttobtb/implementation.so: build/phttobtb/hostcalls.o
	@mkdir -p $(@D)
	$(CXX) -rdynamic -shared \
		build/phttobtb/wrapper.o build/phttobtb/hostcalls.o \
		-L $(LUCET_BIN) \
		-Wl,-rpath $(LUCET_BIN) \
		 -Wl,--whole-archive -l:liblucet_unified.a  -Wl,--no-whole-archive -ldl -lrt -o $@

build/interlock/implementation.so: $(LUCET_BIN)/liblucet_unified.a
build/interlock/implementation.so: build/interlock/wrapper.o
build/interlock/implementation.so: build/interlock/hostcalls.o
	@mkdir -p $(@D)
	$(CXX) -rdynamic -shared \
		build/interlock/wrapper.o build/interlock/hostcalls.o \
		-L $(LUCET_BIN) \
		-Wl,-rpath $(LUCET_BIN) \
		 -Wl,--whole-archive -l:liblucet_unified.a  -Wl,--no-whole-archive -ldl -lrt -o $@

build/lucet/module.so: build/lucet/module.wasm
	@mkdir -p $(@D)
	$(LUCETC) $(LUCETC_FLAGS) --emit=so \
		--bindings=bindings.json \
		--bindings=$(LUCET_WASI)/bindings.json \
		$< -o $@

build/lucet_unroll/module.so: build/lucet_unroll/module.wasm
	@mkdir -p $(@D)
	$(LUCETC) $(LUCETC_FLAGS) --emit=so \
		--bindings=bindings.json \
		--bindings=$(LUCET_WASI)/bindings.json \
		$< -o $@

build/loadlfence/module.so: build/lucet/module.wasm
	@mkdir -p $(@D)
	$(LUCETC) $(LUCETC_FLAGS) --emit=so \
		--bindings=bindings.json \
		--bindings=$(LUCET_WASI)/bindings.json \
		$(LOADLFENCE_FLAGS) \
		$< -o $@

build/strawman/module.so: build/lucet/module.wasm
	@mkdir -p $(@D)
	$(LUCETC) $(LUCETC_FLAGS) --emit=so \
		--bindings=bindings.json \
		--bindings=$(LUCET_WASI)/bindings.json \
		$(STRAWMAN_FLAGS) \
		$< -o $@

build/sfi_full/module.so: build/lucet_unroll/module.wasm
	@mkdir -p $(@D)
	$(LUCETC) $(LUCETC_FLAGS) --emit=so \
		--bindings=bindings.json \
		--bindings=$(LUCET_WASI)/bindings.json \
		$(SFI_FULL_FLAGS) \
		$< -o $@

build/cet_full/module.so: build/lucet_unroll/module.wasm
	@mkdir -p $(@D)
	$(LUCETC) $(LUCETC_FLAGS) --emit=so \
		--bindings=bindings.json \
		--bindings=$(LUCET_WASI)/bindings.json \
		$(CET_FULL_FLAGS) \
		$< -o $@

build/sfi_aslr/module.so: build/lucet/module.wasm
	@mkdir -p $(@D)
	$(LUCETC) $(LUCETC_FLAGS) --emit=so \
		--bindings=bindings.json \
		--bindings=$(LUCET_WASI)/bindings.json \
		$(SFI_ASLR_FLAGS) \
		$< -o $@

build/cet_aslr/module.so: build/lucet/module.wasm
	@mkdir -p $(@D)
	$(LUCETC) $(LUCETC_FLAGS) --emit=so \
		--bindings=bindings.json \
		--bindings=$(LUCET_WASI)/bindings.json \
		$(CET_ASLR_FLAGS) \
		$< -o $@

build/blade/module.so: build/lucet_unroll/module.wasm
	@mkdir -p $(@D)
	$(LUCETC) $(LUCETC_FLAGS) --emit=so \
		--bindings=bindings.json \
		--bindings=$(LUCET_WASI)/bindings.json \
		$(BLADE_FLAGS) \
		$< -o $@

build/phttobtb/module.so: build/lucet_unroll/module.wasm
	@mkdir -p $(@D)
	$(LUCETC) $(LUCETC_FLAGS) --emit=so \
		--bindings=bindings.json \
		--bindings=$(LUCET_WASI)/bindings.json \
		$(PHTTOBTB_FLAGS) \
		$< -o $@

build/interlock/module.so: build/lucet_unroll/module.wasm
	@mkdir -p $(@D)
	$(LUCETC) $(LUCETC_FLAGS) --emit=so \
		--bindings=bindings.json \
		--bindings=$(LUCET_WASI)/bindings.json \
		$(INTERLOCK_FLAGS) \
		$< -o $@

$(LUCETC) $(LUCET_BIN)/liblucet_unified.a $(LUCET_BIN)/sightglass:
	cargo build --release


.PHONY: clean
clean:
	-rm -rf build
