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

# Note this makefile uses the CET binaries only if REALLY_USE_CET is defined
ifdef REALLY_USE_CET
	CET_CFLAGS:=-fcf-protection=full
	CET_LINKERFLAGS:=-Wl,-z,ibt -Wl,-z,shstk
	LUCET_SIGHTGLASS_TARGET:=$(LUCET_ROOT)/target-cet
else
	CET_CFLAGS:=
	CET_LINKERFLAGS:=
	LUCET_SIGHTGLASS_TARGET:=$(LUCET_ROOT)/target
endif

LUCETC_FLAGS:=--opt-level speed_and_size --min-reserved-size 4294967296
COMMON_CFLAGS:=--std=c99 -Ofast -Wall -W -Wno-implicit-fallthrough -I$(SIGHTGLASS)/include
UNROLL_FLAGS=-funroll-loops -mllvm --unroll-runtime

LOADLFENCE_FLAGS:=--spectre-mitigation=loadlfence --spectre-disable-core-switching
STRAWMAN_FLAGS:=--spectre-mitigation=strawman --spectre-disable-core-switching
SFI_FLAGS:=--spectre-mitigation=sfi --spectre-disable-core-switching --spectre-disable-btbflush
CET_FLAGS:=--spectre-mitigation=cet --spectre-disable-core-switching
SFI_SBXONLY_FLAGS:=--spectre-mitigation=sfi --spectre-only-sandbox-isolation --spectre-disable-core-switching
CET_SBXONLY_FLAGS:=--spectre-mitigation=cet --spectre-only-sandbox-isolation --spectre-disable-core-switching
BLADE_FLAGS:=--spectre-pht-mitigation=blade
PHTTOBTB_FLAGS:=--spectre-pht-mitigation=phttobtb
CFI_FLAGS:=--spectre-pht-mitigation=cfi


SHOOTOUT_NATIVE_CFLAGS:=-march=native -fPIC \
	-DIMPL_REFERENCE -DUSE_LEND \
	-Dmalloc=lend_malloc -Dcalloc=lend_calloc -Dfree=lend_free

BINARYEN_VERSION=86

TIMESTAMP:=$(shell date --iso=seconds)

ifdef CI
	SIGHTGLASS_ARGS:=--quick
endif

default: run

.PHONY: bench
bench: run

.PHONY: run
#run: build
#	taskset -c 1 $(LUCET_ROOT)/target/release/sightglass -c sightglass.toml $(SIGHTGLASS_ARGS)
#	-rm -rf $(LUCET_ROOT)/../benchmarks/current_sightglass
#	mkdir -p $(LUCET_ROOT)/../benchmarks/current_sightglass
#	mv /tmp/results-latest.csv $(LUCET_ROOT)/../benchmarks/current_sightglass/results-latest.csv
#	python3 $(LUCET_ROOT)/../sfi-spectre-testing/scripts/graph_sightglass.py $(LUCET_ROOT)/../benchmarks/current_sightglass/results-latest.csv
#	mv $(LUCET_ROOT)/../benchmarks/current_sightglass $(LUCET_ROOT)/../benchmarks/sightglass_$(shell date --iso=seconds)

run:
	-rm -rf $(LUCET_ROOT)/../benchmarks/current_sightglass
	mkdir -p $(LUCET_ROOT)/../benchmarks/current_sightglass/sbxonly
	mkdir -p $(LUCET_ROOT)/../benchmarks/current_sightglass/both

	$(LUCET_ROOT)/target/release/sightglass -c reference.toml $(SIGHTGLASS_ARGS)
	cp /tmp/reference-latest.csv $(LUCET_ROOT)/../benchmarks/current_sightglass/sbxonly/reference-latest.csv
	mv /tmp/reference-latest.csv $(LUCET_ROOT)/../benchmarks/current_sightglass/both/reference-latest.csv

	$(LUCET_ROOT)/target/release/sightglass -c sbxonly_sfi.toml $(SIGHTGLASS_ARGS)
	mv /tmp/sbxonly_sfi-latest.csv $(LUCET_ROOT)/../benchmarks/current_sightglass/sbxonly/sbxonly_sfi-latest.csv

	$(LUCET_SIGHTGLASS_TARGET)/release/sightglass -c sbxonly_cet.toml $(SIGHTGLASS_ARGS)
	mv /tmp/sbxonly_cet-latest.csv $(LUCET_ROOT)/../benchmarks/current_sightglass/sbxonly/sbxonly_cet-latest.csv

	$(LUCET_ROOT)/target/release/sightglass -c both_sfi.toml $(SIGHTGLASS_ARGS)
	mv /tmp/both_sfi-latest.csv $(LUCET_ROOT)/../benchmarks/current_sightglass/both/both_sfi-latest.csv

	$(LUCET_SIGHTGLASS_TARGET)/release/sightglass -c both_cet.toml $(SIGHTGLASS_ARGS)
	mv /tmp/both_cet-latest.csv $(LUCET_ROOT)/../benchmarks/current_sightglass/both/both_cet-latest.csv

	python3 $(LUCET_ROOT)/../sfi-spectre-testing/scripts/graph_sightglass.py --usePercent $(LUCET_ROOT)/../benchmarks/current_sightglass/sbxonly/reference-latest.csv $(LUCET_ROOT)/../benchmarks/current_sightglass/sbxonly/sbxonly_sfi-latest.csv $(LUCET_ROOT)/../benchmarks/current_sightglass/sbxonly/sbxonly_cet-latest.csv

	python3 $(LUCET_ROOT)/../sfi-spectre-testing/scripts/graph_sightglass.py $(LUCET_ROOT)/../benchmarks/current_sightglass/both/reference-latest.csv $(LUCET_ROOT)/../benchmarks/current_sightglass/both/both_sfi-latest.csv $(LUCET_ROOT)/../benchmarks/current_sightglass/both/both_cet-latest.csv

	mv $(LUCET_ROOT)/../benchmarks/current_sightglass $(LUCET_ROOT)/../benchmarks/sightglass_$(shell date --iso=seconds)

run_pht:
	-rm -rf $(LUCET_ROOT)/../benchmarks/current_sightglass_pht
	mkdir $(LUCET_ROOT)/../benchmarks/current_sightglass_pht

	$(LUCET_ROOT)/target/release/sightglass -c pht.toml $(SIGHTGLASS_ARGS)
	mv /tmp/results-latest.csv $(LUCET_ROOT)/../benchmarks/current_sightglass_pht/results-latest.csv

	python3 $(LUCET_ROOT)/../sfi-spectre-testing/scripts/graph_sightglass.py $(LUCET_ROOT)/../benchmarks/current_sightglass_pht/results-latest.csv
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

build: build/sfi/implementation.so
build: build/sfi/module.so

build: build/cet/implementation.so
build: build/cet/module.so

build: build/sfi_sbxonly/implementation.so
build: build/sfi_sbxonly/module.so

build: build/cet_sbxonly/implementation.so
build: build/cet_sbxonly/module.so

build: build/blade/implementation.so
build: build/blade/module.so

build: build/phttobtb/implementation.so
build: build/phttobtb/module.so

build: build/cfi/implementation.so
build: build/cfi/module.so

build: build/blade_unroll/implementation.so
build: build/blade_unroll/module.so

build: build/phttobtb_unroll/implementation.so
build: build/phttobtb_unroll/module.so

build: build/cfi_unroll/implementation.so
build: build/cfi_unroll/module.so

build: $(LUCET_ROOT)/target/release/sightglass

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
build/sfi/%.o: %.c
	@mkdir -p $(@D)
	$(CC) --std=c99 -fPIC -D_GNU_SOURCE -g3 $(COMMON_CFLAGS) \
		-fvisibility=default \
		-I$(LUCET_RUNTIME)/include \
		-I$(LUCET_WASI)/include \
		-DWASM_MODULE=$(abspath build/sfi/module.so) \
		-c $^ -o $@
build/cet/%.o: %.c
	@mkdir -p $(@D)
	$(CC) --std=c99 -fPIC -D_GNU_SOURCE -g3 $(COMMON_CFLAGS) $(CET_CFLAGS) \
		-fvisibility=default \
		-I$(LUCET_RUNTIME)/include \
		-I$(LUCET_WASI)/include \
		-DWASM_MODULE=$(abspath build/cet/module.so) \
		-c $^ -o $@
build/sfi_sbxonly/%.o: %.c
	@mkdir -p $(@D)
	$(CC) --std=c99 -fPIC -D_GNU_SOURCE -g3 $(COMMON_CFLAGS) \
		-fvisibility=default \
		-I$(LUCET_RUNTIME)/include \
		-I$(LUCET_WASI)/include \
		-DWASM_MODULE=$(abspath build/sfi_sbxonly/module.so) \
		-c $^ -o $@
build/cet_sbxonly/%.o: %.c
	@mkdir -p $(@D)
	$(CC) --std=c99 -fPIC -D_GNU_SOURCE -g3 $(COMMON_CFLAGS) $(CET_CFLAGS) \
		-fvisibility=default \
		-I$(LUCET_RUNTIME)/include \
		-I$(LUCET_WASI)/include \
		-DWASM_MODULE=$(abspath build/cet_sbxonly/module.so) \
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
build/cfi/%.o: %.c
	@mkdir -p $(@D)
	$(CC) --std=c99 -fPIC -D_GNU_SOURCE -g3 $(COMMON_CFLAGS) \
		-fvisibility=default \
		-I$(LUCET_RUNTIME)/include \
		-I$(LUCET_WASI)/include \
		-DWASM_MODULE=$(abspath build/cfi/module.so) \
		-c $^ -o $@
build/blade_unroll/%.o: %.c
	@mkdir -p $(@D)
	$(CC) --std=c99 -fPIC -D_GNU_SOURCE -g3 $(COMMON_CFLAGS) \
		-fvisibility=default \
		-I$(LUCET_RUNTIME)/include \
		-I$(LUCET_WASI)/include \
		-DWASM_MODULE=$(abspath build/blade_unroll/module.so) \
		-c $^ -o $@
build/phttobtb_unroll/%.o: %.c
	@mkdir -p $(@D)
	$(CC) --std=c99 -fPIC -D_GNU_SOURCE -g3 $(COMMON_CFLAGS) \
		-fvisibility=default \
		-I$(LUCET_RUNTIME)/include \
		-I$(LUCET_WASI)/include \
		-DWASM_MODULE=$(abspath build/phttobtb_unroll/module.so) \
		-c $^ -o $@
build/cfi_unroll/%.o: %.c
	@mkdir -p $(@D)
	$(CC) --std=c99 -fPIC -D_GNU_SOURCE -g3 $(COMMON_CFLAGS) \
		-fvisibility=default \
		-I$(LUCET_RUNTIME)/include \
		-I$(LUCET_WASI)/include \
		-DWASM_MODULE=$(abspath build/cfi_unroll/module.so) \
		-c $^ -o $@

build/lucet/implementation.so: $(LUCET_ROOT)/target/release/liblucet_unified.a
build/lucet/implementation.so: build/lucet/wrapper.o
build/lucet/implementation.so: build/lucet/hostcalls.o
	@mkdir -p $(@D)
	$(CXX) -rdynamic -shared \
		build/lucet/wrapper.o build/lucet/hostcalls.o \
		-L $(LUCET_ROOT)/target/release \
		-Wl,-rpath $(LUCET_ROOT)/target/release \
		 -Wl,--whole-archive -l:liblucet_unified.a  -Wl,--no-whole-archive -ldl -lrt -o $@

build/lucet_unroll/implementation.so: $(LUCET_ROOT)/target/release/liblucet_unified.a
build/lucet_unroll/implementation.so: build/lucet_unroll/wrapper.o
build/lucet_unroll/implementation.so: build/lucet_unroll/hostcalls.o
	@mkdir -p $(@D)
	$(CXX) -rdynamic -shared \
		build/lucet_unroll/wrapper.o build/lucet_unroll/hostcalls.o \
		-L $(LUCET_ROOT)/target/release \
		-Wl,-rpath $(LUCET_ROOT)/target/release \
		 -Wl,--whole-archive -l:liblucet_unified.a  -Wl,--no-whole-archive -ldl -lrt -o $@

build/loadlfence/implementation.so: $(LUCET_ROOT)/target/release/liblucet_unified.a
build/loadlfence/implementation.so: build/loadlfence/wrapper.o
build/loadlfence/implementation.so: build/loadlfence/hostcalls.o
	@mkdir -p $(@D)
	$(CXX) -rdynamic -shared \
		build/loadlfence/wrapper.o build/loadlfence/hostcalls.o \
		-L $(LUCET_ROOT)/target/release \
		-Wl,-rpath $(LUCET_ROOT)/target/release \
		 -Wl,--whole-archive -l:liblucet_unified.a  -Wl,--no-whole-archive -ldl -lrt -o $@

build/strawman/implementation.so: $(LUCET_ROOT)/target/release/liblucet_unified.a
build/strawman/implementation.so: build/strawman/wrapper.o
build/strawman/implementation.so: build/strawman/hostcalls.o
	@mkdir -p $(@D)
	$(CXX) -rdynamic -shared \
		build/strawman/wrapper.o build/strawman/hostcalls.o \
		-L $(LUCET_ROOT)/target/release \
		-Wl,-rpath $(LUCET_ROOT)/target/release \
		 -Wl,--whole-archive -l:liblucet_unified.a  -Wl,--no-whole-archive -ldl -lrt -o $@

build/sfi/implementation.so: $(LUCET_ROOT)/target/release/liblucet_unified.a
build/sfi/implementation.so: build/sfi/wrapper.o
build/sfi/implementation.so: build/sfi/hostcalls.o
	@mkdir -p $(@D)
	$(CXX) -rdynamic -shared \
		build/sfi/wrapper.o build/sfi/hostcalls.o \
		-L $(LUCET_ROOT)/target/release \
		-Wl,-rpath $(LUCET_ROOT)/target/release \
		 -Wl,--whole-archive -l:liblucet_unified.a  -Wl,--no-whole-archive -ldl -lrt -o $@

build/cet/implementation.so: $(LUCET_ROOT)/target/release/liblucet_unified.a
build/cet/implementation.so: build/cet/wrapper.o
build/cet/implementation.so: build/cet/hostcalls.o
	@mkdir -p $(@D)
	$(CXX) -rdynamic -shared $(CET_CFLAGS) $(CET_LINKERFLAGS) \
		build/cet/wrapper.o build/cet/hostcalls.o \
		-L $(LUCET_SIGHTGLASS_TARGET)/release \
		-Wl,-rpath $(LUCET_SIGHTGLASS_TARGET)/release \
		 -Wl,--whole-archive -l:liblucet_unified.a  -Wl,--no-whole-archive -ldl -lrt -o $@

build/sfi_sbxonly/implementation.so: $(LUCET_ROOT)/target/release/liblucet_unified.a
build/sfi_sbxonly/implementation.so: build/sfi_sbxonly/wrapper.o
build/sfi_sbxonly/implementation.so: build/sfi_sbxonly/hostcalls.o
	@mkdir -p $(@D)
	$(CXX) -rdynamic -shared \
		build/sfi_sbxonly/wrapper.o build/sfi_sbxonly/hostcalls.o \
		-L $(LUCET_ROOT)/target/release \
		-Wl,-rpath $(LUCET_ROOT)/target/release \
		 -Wl,--whole-archive -l:liblucet_unified.a  -Wl,--no-whole-archive -ldl -lrt -o $@

build/cet_sbxonly/implementation.so: $(LUCET_ROOT)/target/release/liblucet_unified.a
build/cet_sbxonly/implementation.so: build/cet_sbxonly/wrapper.o
build/cet_sbxonly/implementation.so: build/cet_sbxonly/hostcalls.o
	@mkdir -p $(@D)
	$(CXX) -rdynamic -shared $(CET_CFLAGS) $(CET_LINKERFLAGS) \
		build/cet_sbxonly/wrapper.o build/cet_sbxonly/hostcalls.o \
		-L $(LUCET_SIGHTGLASS_TARGET)/release \
		-Wl,-rpath $(LUCET_SIGHTGLASS_TARGET)/release \
		 -Wl,--whole-archive -l:liblucet_unified.a  -Wl,--no-whole-archive -ldl -lrt -o $@

build/blade/implementation.so: $(LUCET_ROOT)/target/release/liblucet_unified.a
build/blade/implementation.so: build/blade/wrapper.o
build/blade/implementation.so: build/blade/hostcalls.o
	@mkdir -p $(@D)
	$(CXX) -rdynamic -shared \
		build/blade/wrapper.o build/blade/hostcalls.o \
		-L $(LUCET_ROOT)/target/release \
		-Wl,-rpath $(LUCET_ROOT)/target/release \
		 -Wl,--whole-archive -l:liblucet_unified.a  -Wl,--no-whole-archive -ldl -lrt -o $@

build/phttobtb/implementation.so: $(LUCET_ROOT)/target/release/liblucet_unified.a
build/phttobtb/implementation.so: build/phttobtb/wrapper.o
build/phttobtb/implementation.so: build/phttobtb/hostcalls.o
	@mkdir -p $(@D)
	$(CXX) -rdynamic -shared \
		build/phttobtb/wrapper.o build/phttobtb/hostcalls.o \
		-L $(LUCET_ROOT)/target/release \
		-Wl,-rpath $(LUCET_ROOT)/target/release \
		 -Wl,--whole-archive -l:liblucet_unified.a  -Wl,--no-whole-archive -ldl -lrt -o $@

build/cfi/implementation.so: $(LUCET_ROOT)/target/release/liblucet_unified.a
build/cfi/implementation.so: build/cfi/wrapper.o
build/cfi/implementation.so: build/cfi/hostcalls.o
	@mkdir -p $(@D)
	$(CXX) -rdynamic -shared \
		build/cfi/wrapper.o build/cfi/hostcalls.o \
		-L $(LUCET_ROOT)/target/release \
		-Wl,-rpath $(LUCET_ROOT)/target/release \
		 -Wl,--whole-archive -l:liblucet_unified.a  -Wl,--no-whole-archive -ldl -lrt -o $@

build/blade_unroll/implementation.so: $(LUCET_ROOT)/target/release/liblucet_unified.a
build/blade_unroll/implementation.so: build/blade_unroll/wrapper.o
build/blade_unroll/implementation.so: build/blade_unroll/hostcalls.o
	@mkdir -p $(@D)
	$(CXX) -rdynamic -shared \
		build/blade_unroll/wrapper.o build/blade_unroll/hostcalls.o \
		-L $(LUCET_ROOT)/target/release \
		-Wl,-rpath $(LUCET_ROOT)/target/release \
		 -Wl,--whole-archive -l:liblucet_unified.a  -Wl,--no-whole-archive -ldl -lrt -o $@

build/phttobtb_unroll/implementation.so: $(LUCET_ROOT)/target/release/liblucet_unified.a
build/phttobtb_unroll/implementation.so: build/phttobtb_unroll/wrapper.o
build/phttobtb_unroll/implementation.so: build/phttobtb_unroll/hostcalls.o
	@mkdir -p $(@D)
	$(CXX) -rdynamic -shared \
		build/phttobtb_unroll/wrapper.o build/phttobtb_unroll/hostcalls.o \
		-L $(LUCET_ROOT)/target/release \
		-Wl,-rpath $(LUCET_ROOT)/target/release \
		 -Wl,--whole-archive -l:liblucet_unified.a  -Wl,--no-whole-archive -ldl -lrt -o $@

build/cfi_unroll/implementation.so: $(LUCET_ROOT)/target/release/liblucet_unified.a
build/cfi_unroll/implementation.so: build/cfi_unroll/wrapper.o
build/cfi_unroll/implementation.so: build/cfi_unroll/hostcalls.o
	@mkdir -p $(@D)
	$(CXX) -rdynamic -shared \
		build/cfi_unroll/wrapper.o build/cfi_unroll/hostcalls.o \
		-L $(LUCET_ROOT)/target/release \
		-Wl,-rpath $(LUCET_ROOT)/target/release \
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

build/loadlfence/module.so: build/lucet_unroll/module.wasm
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

build/sfi/module.so: build/lucet/module.wasm
	@mkdir -p $(@D)
	$(LUCETC) $(LUCETC_FLAGS) --emit=so \
		--bindings=bindings.json \
		--bindings=$(LUCET_WASI)/bindings.json \
		$(SFI_FLAGS) \
		$< -o $@

build/cet/module.so: build/lucet/module.wasm
	@mkdir -p $(@D)
	$(LUCETC) $(LUCETC_FLAGS) --emit=so \
		--bindings=bindings.json \
		--bindings=$(LUCET_WASI)/bindings.json \
		$(CET_FLAGS) \
		$< -o $@

build/sfi_sbxonly/module.so: build/lucet/module.wasm
	@mkdir -p $(@D)
	$(LUCETC) $(LUCETC_FLAGS) --emit=so \
		--bindings=bindings.json \
		--bindings=$(LUCET_WASI)/bindings.json \
		$(SFI_SBXONLY_FLAGS) \
		$< -o $@

build/cet_sbxonly/module.so: build/lucet/module.wasm
	@mkdir -p $(@D)
	$(LUCETC) $(LUCETC_FLAGS) --emit=so \
		--bindings=bindings.json \
		--bindings=$(LUCET_WASI)/bindings.json \
		$(CET_SBXONLY_FLAGS) \
		$< -o $@

build/blade/module.so: build/lucet/module.wasm
	@mkdir -p $(@D)
	$(LUCETC) $(LUCETC_FLAGS) --emit=so \
		--bindings=bindings.json \
		--bindings=$(LUCET_WASI)/bindings.json \
		$(BLADE_FLAGS) \
		$< -o $@

build/phttobtb/module.so: build/lucet/module.wasm
	@mkdir -p $(@D)
	$(LUCETC) $(LUCETC_FLAGS) --emit=so \
		--bindings=bindings.json \
		--bindings=$(LUCET_WASI)/bindings.json \
		$(PHTTOBTB_FLAGS) \
		$< -o $@

build/cfi/module.so: build/lucet/module.wasm
	@mkdir -p $(@D)
	$(LUCETC) $(LUCETC_FLAGS) --emit=so \
		--bindings=bindings.json \
		--bindings=$(LUCET_WASI)/bindings.json \
		$(CFI_FLAGS) \
		$< -o $@

build/blade_unroll/module.so: build/lucet_unroll/module.wasm
	@mkdir -p $(@D)
	$(LUCETC) $(LUCETC_FLAGS) --emit=so \
		--bindings=bindings.json \
		--bindings=$(LUCET_WASI)/bindings.json \
		$(BLADE_FLAGS) \
		$< -o $@

build/phttobtb_unroll/module.so: build/lucet_unroll/module.wasm
	@mkdir -p $(@D)
	$(LUCETC) $(LUCETC_FLAGS) --emit=so \
		--bindings=bindings.json \
		--bindings=$(LUCET_WASI)/bindings.json \
		$(PHTTOBTB_FLAGS) \
		$< -o $@

build/cfi_unroll/module.so: build/lucet_unroll/module.wasm
	@mkdir -p $(@D)
	$(LUCETC) $(LUCETC_FLAGS) --emit=so \
		--bindings=bindings.json \
		--bindings=$(LUCET_WASI)/bindings.json \
		$(CFI_FLAGS) \
		$< -o $@

$(LUCETC) $(LUCET_ROOT)/target/release/liblucet_unified.a $(LUCET_ROOT)/target/release/sightglass:
	cargo build --release


.PHONY: clean
clean:
	-rm -rf build
