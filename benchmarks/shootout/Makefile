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

LUCETC_FLAGS:=--opt-level speed_and_size --min-reserved-size 4294967296
COMMON_CFLAGS:=--std=c99 -Ofast -Wall -W -I$(SIGHTGLASS)/include

LOADLFENCE_FLAGS:=--spectre-mitigation=loadlfence
STRAWMAN_FLAGS:=--spectre-mitigation=strawman
SFI_FLAGS:=--spectre-mitigation=sfi
CET_FLAGS:=--spectre-mitigation=cet
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
run: build
	taskset -c 1 $(LUCET_ROOT)/target/release/sightglass -c sightglass.toml $(SIGHTGLASS_ARGS)
	-rm -r $(LUCET_ROOT)/benchmarks/current_sightglass
	mkdir -p $(LUCET_ROOT)/benchmarks/current_sightglass
	mv /tmp/results-latest.csv $(LUCET_ROOT)/benchmarks/current_sightglass/results-latest.csv
	python3 $(LUCET_ROOT)/sfi-spectre-testing/scripts/graph_sightglass.py $(LUCET_ROOT)/benchmarks/current_sightglass/results-latest.csv
	mv $(LUCET_ROOT)/benchmarks/current_sightglass $(LUCET_ROOT)/benchmarks/sightglass_$(shell date --iso=seconds)

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

build/loadlfence/module.wasm.unoptimized: $(patsubst %.c, %.o, $(addprefix build/lucet/shootout/, $(notdir $(SHOOTOUT_SRCS))))
	@mkdir -p $(@D)
	$(WASI_CC) $^ -o $@ -nostartfiles -Wl,--no-entry -Wl,--export-all

build/loadlfence/module.wasm: build/lucet/module.wasm.unoptimized
	$(WASM_OPT) -mvp --disable-mutable-globals -O4 -o $@ $^

build/loadlfence/module.so: build/lucet/module.wasm
	@mkdir -p $(@D)
	$(LUCETC) $(LUCETC_FLAGS) --emit=so \
		--bindings=bindings.json \
		--bindings=$(LUCET_WASI)/bindings.json \
		$(LOADLFENCE_FLAGS) \
		$< -o $@


build/loadlfence/implementation.so: build/lucet/implementation.so
	@mkdir -p $(@D)
	cp build/lucet/implementation.so $@

build/strawman/implementation.so: build/lucet/implementation.so
	@mkdir -p $(@D)
	cp build/lucet/implementation.so $@

build/sfi/implementation.so: build/lucet/implementation.so
	@mkdir -p $(@D)
	cp build/lucet/implementation.so $@

build/cet/implementation.so: build/lucet/implementation.so
	@mkdir -p $(@D)
	cp build/lucet/implementation.so $@

build/blade/implementation.so: build/lucet/implementation.so
	@mkdir -p $(@D)
	cp build/lucet/implementation.so $@




build/strawman/module.wasm.unoptimized: $(patsubst %.c, %.o, $(addprefix build/lucet/shootout/, $(notdir $(SHOOTOUT_SRCS))))
	@mkdir -p $(@D)
	$(WASI_CC) $^ -o $@ -nostartfiles -Wl,--no-entry -Wl,--export-all

build/strawman/module.wasm: build/lucet/module.wasm.unoptimized
	$(WASM_OPT) -mvp --disable-mutable-globals -O4 -o $@ $^

build/strawman/module.so: build/lucet/module.wasm
	@mkdir -p $(@D)
	$(LUCETC) $(LUCETC_FLAGS) --emit=so \
		--bindings=bindings.json \
		--bindings=$(LUCET_WASI)/bindings.json \
		$(STRAWMAN_FLAGS) \
		$< -o $@


build/sfi/module.wasm.unoptimized: $(patsubst %.c, %.o, $(addprefix build/lucet/shootout/, $(notdir $(SHOOTOUT_SRCS))))
	@mkdir -p $(@D)
	$(WASI_CC) $^ -o $@ -nostartfiles -Wl,--no-entry -Wl,--export-all

build/sfi/module.wasm: build/lucet/module.wasm.unoptimized
	$(WASM_OPT) -mvp --disable-mutable-globals -O4 -o $@ $^

build/sfi/module.so: build/lucet/module.wasm
	@mkdir -p $(@D)
	$(LUCETC) $(LUCETC_FLAGS) --emit=so \
		--bindings=bindings.json \
		--bindings=$(LUCET_WASI)/bindings.json \
		$(SFI_FLAGS) \
		$< -o $@



build/cet/module.wasm.unoptimized: $(patsubst %.c, %.o, $(addprefix build/lucet/shootout/, $(notdir $(SHOOTOUT_SRCS))))
	@mkdir -p $(@D)
	$(WASI_CC) $^ -o $@ -nostartfiles -Wl,--no-entry -Wl,--export-all

build/cet/module.wasm: build/lucet/module.wasm.unoptimized
	$(WASM_OPT) -mvp --disable-mutable-globals -O4 -o $@ $^

build/cet/module.so: build/lucet/module.wasm
	@mkdir -p $(@D)
	$(LUCETC) $(LUCETC_FLAGS) --emit=so \
		--bindings=bindings.json \
		--bindings=$(LUCET_WASI)/bindings.json \
		$(CET_FLAGS) \
		$< -o $@


build/blade/module.wasm.unoptimized: $(patsubst %.c, %.o, $(addprefix build/lucet/shootout/, $(notdir $(SHOOTOUT_SRCS))))
	@mkdir -p $(@D)
	$(WASI_CC) $^ -o $@ -nostartfiles -Wl,--no-entry -Wl,--export-all

build/blade/module.wasm: build/lucet/module.wasm.unoptimized
	$(WASM_OPT) -mvp --disable-mutable-globals -O4 -o $@ $^

build/blade/module.so: build/lucet/module.wasm
	@mkdir -p $(@D)
	$(LUCETC) $(LUCETC_FLAGS) --emit=so \
		--bindings=bindings.json \
		--bindings=$(LUCET_WASI)/bindings.json \
		$(BLADE_FLAGS) \
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

build/lucet/implementation.so: $(LUCET_ROOT)/target/release/liblucet_runtime.so
build/lucet/implementation.so: $(LUCET_ROOT)/target/release/liblucet_wasi.so
build/lucet/implementation.so: build/lucet/wrapper.o
build/lucet/implementation.so: build/lucet/hostcalls.o
	@mkdir -p $(@D)
	$(CC) -rdynamic -shared \
		build/lucet/wrapper.o build/lucet/hostcalls.o \
		-L $(LUCET_ROOT)/target/release \
		-Wl,-rpath $(LUCET_ROOT)/target/release \
		-llucet_runtime -llucet_wasi -ldl -lrt -o $@

$(LUCET_ROOT)/target/release/sightglass:
	cargo build --release -p sightglass

$(LUCETC):
	cargo build --release -p lucetc

.PHONY: $(LUCET_ROOT)/target/release/liblucet_runtime.so
$(LUCET_ROOT)/target/release/liblucet_runtime.so:
	cargo build --release -p lucet-runtime


.PHONY: $(LUCET_ROOT)/target/release/liblucet_wasi.so
$(LUCET_ROOT)/target/release/liblucet_wasi.so:
	cargo build --release -p lucet-wasi

.PHONY: clean
clean:
	-rm -rf build
