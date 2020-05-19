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
	LUCET_SIGHTGLASS_TARGET:=$(LUCET_ROOT)/target-cet
else
	LUCET_SIGHTGLASS_TARGET:=$(LUCET_ROOT)/target
endif

LUCETC_FLAGS:=--opt-level speed_and_size --min-reserved-size 4294967296
COMMON_CFLAGS:=--std=c99 -Ofast -Wall -W -Wno-implicit-fallthrough -I$(SIGHTGLASS)/include
CET_CFLAGS:=-fcf-protection=full

LOADLFENCE_FLAGS:=--spectre-mitigation=loadlfence
STRAWMAN_FLAGS:=--spectre-mitigation=strawman
SFI_FLAGS:=--spectre-mitigation=sfi
CET_FLAGS:=--spectre-mitigation=cet
SFI_NOBLADE_FLAGS:=--spectre-mitigation=sfi --spectre-pht-mitigation=none
CET_NOBLADE_FLAGS:=--spectre-mitigation=cet --spectre-pht-mitigation=none
BLADE_FLAGS:=--spectre-pht-mitigation=blade


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
	mkdir -p $(LUCET_ROOT)/../benchmarks/current_sightglass

	$(LUCET_ROOT)/target/release/sightglass -c reference.toml $(SIGHTGLASS_ARGS)
	mv /tmp/reference-latest.csv $(LUCET_ROOT)/../benchmarks/current_sightglass/reference-latest.csv

	$(LUCET_ROOT)/target/release/sightglass -c blade_sfi.toml $(SIGHTGLASS_ARGS)
	mv /tmp/blade_sfi-latest.csv $(LUCET_ROOT)/../benchmarks/current_sightglass/blade_sfi-latest.csv

	$(LUCET_SIGHTGLASS_TARGET)/release/sightglass -c cet.toml $(SIGHTGLASS_ARGS)
	mv /tmp/cet-latest.csv $(LUCET_ROOT)/../benchmarks/current_sightglass/cet-latest.csv

	python3 $(LUCET_ROOT)/../sfi-spectre-testing/scripts/graph_sightglass.py $(LUCET_ROOT)/../benchmarks/current_sightglass/reference-latest.csv $(LUCET_ROOT)/../benchmarks/current_sightglass/blade_sfi-latest.csv $(LUCET_ROOT)/../benchmarks/current_sightglass/cet-latest.csv
	mv $(LUCET_ROOT)/../benchmarks/current_sightglass $(LUCET_ROOT)/../benchmarks/sightglass_$(shell date --iso=seconds)


.PHONY: build
build: $(LUCETC)
build: build/native/implementation.so

build: build/lucet/implementation.so
build: build/lucet/module.so

build: build/loadlfence/implementation.so
build: build/loadlfence/module.so

build: build/strawman/implementation.so
build: build/strawman/module.so

build: build/sfi/implementation.so
build: build/sfi/module.so

build: build/cet/implementation.so
build: build/cet/module.so

build: build/sfi_noblade/implementation.so
build: build/sfi_noblade/module.so

build: build/cet_noblade/implementation.so
build: build/cet_noblade/module.so

build: build/blade/implementation.so
build: build/blade/module.so

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

build/lucet/module.so: build/lucet/module.wasm
	@mkdir -p $(@D)
	$(LUCETC) $(LUCETC_FLAGS) --emit=so \
		--bindings=bindings.json \
		--bindings=$(LUCET_WASI)/bindings.json \
		$< -o $@

build/lucet/module.clif: build/lucet/module.wasm
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
build/sfi_noblade/%.o: %.c
	@mkdir -p $(@D)
	$(CC) --std=c99 -fPIC -D_GNU_SOURCE -g3 $(COMMON_CFLAGS) \
		-fvisibility=default \
		-I$(LUCET_RUNTIME)/include \
		-I$(LUCET_WASI)/include \
		-DWASM_MODULE=$(abspath build/sfi_noblade/module.so) \
		-c $^ -o $@
build/cet_noblade/%.o: %.c
	@mkdir -p $(@D)
	$(CC) --std=c99 -fPIC -D_GNU_SOURCE -g3 $(COMMON_CFLAGS) $(CET_CFLAGS) \
		-fvisibility=default \
		-I$(LUCET_RUNTIME)/include \
		-I$(LUCET_WASI)/include \
		-DWASM_MODULE=$(abspath build/cet_noblade/module.so) \
		-c $^ -o $@
build/blade/%.o: %.c
	@mkdir -p $(@D)
	$(CC) --std=c99 -fPIC -D_GNU_SOURCE -g3 $(COMMON_CFLAGS) \
		-fvisibility=default \
		-I$(LUCET_RUNTIME)/include \
		-I$(LUCET_WASI)/include \
		-DWASM_MODULE=$(abspath build/blade/module.so) \
		-c $^ -o $@

build/lucet/implementation.so: $(LUCET_ROOT)/target/release/liblucet_unified.a
build/lucet/implementation.so: build/lucet/wrapper.o
build/lucet/implementation.so: build/lucet/hostcalls.o
	@mkdir -p $(@D)
	$(CC) -rdynamic -shared \
		build/lucet/wrapper.o build/lucet/hostcalls.o \
		-L $(LUCET_ROOT)/target/release \
		-Wl,-rpath $(LUCET_ROOT)/target/release \
		 -Wl,--whole-archive -l:liblucet_unified.a  -Wl,--no-whole-archive -ldl -lrt -o $@

build/loadlfence/implementation.so: $(LUCET_ROOT)/target/release/liblucet_unified.a
build/loadlfence/implementation.so: build/loadlfence/wrapper.o
build/loadlfence/implementation.so: build/loadlfence/hostcalls.o
	@mkdir -p $(@D)
	$(CC) -rdynamic -shared \
		build/loadlfence/wrapper.o build/loadlfence/hostcalls.o \
		-L $(LUCET_ROOT)/target/release \
		-Wl,-rpath $(LUCET_ROOT)/target/release \
		 -Wl,--whole-archive -l:liblucet_unified.a  -Wl,--no-whole-archive -ldl -lrt -o $@

build/strawman/implementation.so: $(LUCET_ROOT)/target/release/liblucet_unified.a
build/strawman/implementation.so: build/strawman/wrapper.o
build/strawman/implementation.so: build/strawman/hostcalls.o
	@mkdir -p $(@D)
	$(CC) -rdynamic -shared \
		build/strawman/wrapper.o build/strawman/hostcalls.o \
		-L $(LUCET_ROOT)/target/release \
		-Wl,-rpath $(LUCET_ROOT)/target/release \
		 -Wl,--whole-archive -l:liblucet_unified.a  -Wl,--no-whole-archive -ldl -lrt -o $@

build/sfi/implementation.so: $(LUCET_ROOT)/target/release/liblucet_unified.a
build/sfi/implementation.so: build/sfi/wrapper.o
build/sfi/implementation.so: build/sfi/hostcalls.o
	@mkdir -p $(@D)
	$(CC) -rdynamic -shared \
		build/sfi/wrapper.o build/sfi/hostcalls.o \
		-L $(LUCET_ROOT)/target/release \
		-Wl,-rpath $(LUCET_ROOT)/target/release \
		 -Wl,--whole-archive -l:liblucet_unified.a  -Wl,--no-whole-archive -ldl -lrt -o $@

build/cet/implementation.so: $(LUCET_ROOT)/target/release/liblucet_unified.a
build/cet/implementation.so: build/cet/wrapper.o
build/cet/implementation.so: build/cet/hostcalls.o
	@mkdir -p $(@D)
	$(CC) -rdynamic -shared $(CET_CFLAGS) \
		build/cet/wrapper.o build/cet/hostcalls.o \
		-L $(LUCET_SIGHTGLASS_TARGET)/release \
		-Wl,-rpath $(LUCET_SIGHTGLASS_TARGET)/release \
		 -Wl,--whole-archive -l:liblucet_unified.a  -Wl,--no-whole-archive -ldl -lrt -o $@

build/sfi_noblade/implementation.so: $(LUCET_ROOT)/target/release/liblucet_unified.a
build/sfi_noblade/implementation.so: build/sfi_noblade/wrapper.o
build/sfi_noblade/implementation.so: build/sfi_noblade/hostcalls.o
	@mkdir -p $(@D)
	$(CC) -rdynamic -shared \
		build/sfi_noblade/wrapper.o build/sfi_noblade/hostcalls.o \
		-L $(LUCET_ROOT)/target/release \
		-Wl,-rpath $(LUCET_ROOT)/target/release \
		 -Wl,--whole-archive -l:liblucet_unified.a  -Wl,--no-whole-archive -ldl -lrt -o $@

build/cet_noblade/implementation.so: $(LUCET_ROOT)/target/release/liblucet_unified.a
build/cet_noblade/implementation.so: build/cet_noblade/wrapper.o
build/cet_noblade/implementation.so: build/cet_noblade/hostcalls.o
	@mkdir -p $(@D)
	$(CC) -rdynamic -shared $(CET_CFLAGS) \
		build/cet_noblade/wrapper.o build/cet_noblade/hostcalls.o \
		-L $(LUCET_SIGHTGLASS_TARGET)/release \
		-Wl,-rpath $(LUCET_SIGHTGLASS_TARGET)/release \
		 -Wl,--whole-archive -l:liblucet_unified.a  -Wl,--no-whole-archive -ldl -lrt -o $@

build/blade/implementation.so: $(LUCET_ROOT)/target/release/liblucet_unified.a
build/blade/implementation.so: build/blade/wrapper.o
build/blade/implementation.so: build/blade/hostcalls.o
	@mkdir -p $(@D)
	$(CC) -rdynamic -shared \
		build/blade/wrapper.o build/blade/hostcalls.o \
		-L $(LUCET_ROOT)/target/release \
		-Wl,-rpath $(LUCET_ROOT)/target/release \
		 -Wl,--whole-archive -l:liblucet_unified.a  -Wl,--no-whole-archive -ldl -lrt -o $@

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

build/sfi_noblade/module.so: build/lucet/module.wasm
	@mkdir -p $(@D)
	$(LUCETC) $(LUCETC_FLAGS) --emit=so \
		--bindings=bindings.json \
		--bindings=$(LUCET_WASI)/bindings.json \
		$(SFI_NOBLADE_FLAGS) \
		$< -o $@

build/cet_noblade/module.so: build/lucet/module.wasm
	@mkdir -p $(@D)
	$(LUCETC) $(LUCETC_FLAGS) --emit=so \
		--bindings=bindings.json \
		--bindings=$(LUCET_WASI)/bindings.json \
		$(CET_NOBLADE_FLAGS) \
		$< -o $@

build/blade/module.so: build/lucet/module.wasm
	@mkdir -p $(@D)
	$(LUCETC) $(LUCETC_FLAGS) --emit=so \
		--bindings=bindings.json \
		--bindings=$(LUCET_WASI)/bindings.json \
		$(BLADE_FLAGS) \
		$< -o $@

$(LUCETC) $(LUCET_ROOT)/target/release/liblucet_unified.a $(LUCET_ROOT)/target/release/sightglass:
	cargo build --release


.PHONY: clean
clean:
	-rm -rf build
