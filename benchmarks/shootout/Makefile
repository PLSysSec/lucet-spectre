LUCET_ROOT:=$(abspath ../..)

WASI_SDK?=/opt/wasi-sdk
WASI_CC?=$(WASI_SDK)/bin/clang
BINARYEN_DIR?=/opt/binaryen
WASM_OPT?=$(shell command -v wasm-opt || echo $(BINARYEN_DIR)/bin/wasm-opt)

LUCETC:=$(LUCET_ROOT)/target/release/lucetc

LUCET_RUNTIME:=$(LUCET_ROOT)/lucet-runtime
LUCET_WASI:=$(LUCET_ROOT)/lucet-wasi
SIGHTGLASS:=$(LUCET_ROOT)/sightglass

LIBBUILTINS:=$(LUCET_ROOT)/lucet-builtins/build/libbuiltins.so

SHOOTOUT:=$(LUCET_ROOT)/sightglass/benchmarks/shootout
SHOOTOUT_SRCS:=$(shell ls $(SHOOTOUT)/*.c)
SHOOTOUT_NATIVE_OBJS:=
SHOOTOUT_LUCET_OBJS:=

LUCETC_FLAGS:=--opt-level speed --min-reserved-size 4294967296
COMMON_CFLAGS:=--std=c99 -Ofast -Wall -W -I$(SIGHTGLASS)/include
SPECTRE_FLAGS:=--spectre-mitigations-enable
FENCE_FLAGS:=--spectre-baseline-loadfence-enable

SHOOTOUT_NATIVE_CFLAGS:=-march=native -fPIC \
	-DIMPL_REFERENCE -DUSE_LEND \
	-Dmalloc=lend_malloc -Dcalloc=lend_calloc -Dfree=lend_free

SENSIVITYRANGE:=1 2 3 4 5

BINARYEN_VERSION=86

ifdef CI
	SIGHTGLASS_ARGS:=--quick
endif

default: run

.PHONY: bench
bench: run

.PHONY: run
run: build
	$(LUCET_ROOT)/target/debug/sightglass -c sightglass.toml $(SIGHTGLASS_ARGS)
	python3 ../../../sfi-spectre-testing/scripts/shootglass_stats.py /tmp/results-latest.csv 

run_sensitivity: build_sensitivity
	$(LUCET_ROOT)/target/debug/sightglass -c sightglass_sensitivity.toml $(SIGHTGLASS_ARGS)
	python3 ../../../sfi-spectre-testing/scripts/shootglass_stats.py /tmp/results-latest.csv 


.PHONY: build
build: $(LUCETC)
build: build/lucet/implementation.so
build: build/lucet/module.so
build: build/spectre/implementation.so
build: build/spectre/module.so
build: build/fence/implementation.so
build: build/fence/module.so
build: $(LUCET_ROOT)/target/release/sightglass

build_sensitivity: $(addsuffix /implementation.so, $(addprefix build/sensitivity, $(SENSIVITYRANGE) ))
build_sensitivity: $(addsuffix /module.so, $(addprefix build/sensitivity, $(SENSIVITYRANGE) ))	

build/wasm/shootout/%.o: $(SHOOTOUT)/%.c
	@mkdir -p $(@D)
	$(WASI_CC) $(COMMON_CFLAGS) -c $^ -o $@

#build/fence/shootout/%.o: $(SHOOTOUT)/%.c
#	@mkdir -p $(@D)
#	$(WASI_CC) $(COMMON_CFLAGS) -c $^ -o $@

build/wasm/module.wasm.unoptimized: $(patsubst %.c, %.o, $(addprefix build/wasm/shootout/, $(notdir $(SHOOTOUT_SRCS))))
	@mkdir -p $(@D)
	$(WASI_CC) $^ -o $@ -nostartfiles -Wl,--no-entry -Wl,--export-all

build/wasm/module.wasm: build/wasm/module.wasm.unoptimized
	$(WASM_OPT) -mvp --disable-mutable-globals -O4 -o $@ $^

# Don't emit the shared object, we need a saparate link step below.
build/lucet/module.o: build/wasm/module.wasm $(LIBBUILTINS)
	@mkdir -p $(@D)
	$(LUCETC) $(LUCETC_FLAGS) --emit=obj \
		--bindings=bindings.json \
		--bindings=$(LUCET_WASI)/bindings.json \
		--builtins=$(LIBBUILTINS) build/wasm/module.wasm -o $@

build/spectre/module.o: build/wasm/module.wasm $(LIBBUILTINS)
	@mkdir -p $(@D)
	$(LUCETC) $(LUCETC_FLAGS) $(SPECTRE_FLAGS) --emit=obj \
		--bindings=bindings.json \
		--bindings=$(LUCET_WASI)/bindings.json \
		--builtins=$(LIBBUILTINS) build/wasm/module.wasm -o $@

build/sensitivity1/module.o: build/wasm/module.wasm $(LIBBUILTINS)
	@mkdir -p $(@D)
	$(LUCETC) $(LUCETC_FLAGS) --spectre-tblocks-in-ablock=1 --emit=obj \
		--bindings=bindings.json \
		--bindings=$(LUCET_WASI)/bindings.json \
		--builtins=$(LIBBUILTINS) build/wasm/module.wasm -o $@

build/sensitivity2/module.o: build/wasm/module.wasm $(LIBBUILTINS)
	@mkdir -p $(@D)
	$(LUCETC) $(LUCETC_FLAGS) --spectre-tblocks-in-ablock=2 --emit=obj \
		--bindings=bindings.json \
		--bindings=$(LUCET_WASI)/bindings.json \
		--builtins=$(LIBBUILTINS) build/wasm/module.wasm -o $@

build/sensitivity3/module.o: build/wasm/module.wasm $(LIBBUILTINS)
	@mkdir -p $(@D)
	$(LUCETC) $(LUCETC_FLAGS) --spectre-tblocks-in-ablock=3 --emit=obj \
		--bindings=bindings.json \
		--bindings=$(LUCET_WASI)/bindings.json \
		--builtins=$(LIBBUILTINS) build/wasm/module.wasm -o $@

build/sensitivity4/module.o: build/wasm/module.wasm $(LIBBUILTINS)
	@mkdir -p $(@D)
	$(LUCETC) $(LUCETC_FLAGS) --spectre-tblocks-in-ablock=4 --emit=obj \
		--bindings=bindings.json \
		--bindings=$(LUCET_WASI)/bindings.json \
		--builtins=$(LIBBUILTINS) build/wasm/module.wasm -o $@

build/sensitivity5/module.o: build/wasm/module.wasm $(LIBBUILTINS)
	@mkdir -p $(@D)
	$(LUCETC) $(LUCETC_FLAGS) --spectre-tblocks-in-ablock=5 --emit=obj \
		--bindings=bindings.json \
		--bindings=$(LUCET_WASI)/bindings.json \
		--builtins=$(LIBBUILTINS) build/wasm/module.wasm -o $@


build/fence/module.o: build/wasm/module.wasm $(LIBBUILTINS)
	@mkdir -p $(@D)
	$(LUCETC) $(LUCETC_FLAGS) $(FENCE_FLAGS) --emit=obj \
		--bindings=bindings.json \
		--bindings=$(LUCET_WASI)/bindings.json \
		--builtins=$(LIBBUILTINS) build/wasm/module.wasm -o $@

# Because liblucet-runtime-c is dynamically loaded (transitively) by implementation.so, we
# need to link the wasm object to the same libraries.
build/lucet/module.so: build/lucet/module.o
	@mkdir -p $(@D)
	$(CC) -rdynamic -shared \
		-L $(dir $(LIBBUILTINS)) \
		-Wl,-rpath $(dir $(LIBBUILTINS)) \
		build/lucet/module.o -lbuiltins -o $@

build/spectre/module.so: build/spectre/module.o
	@mkdir -p $(@D)
	$(CC) -rdynamic -shared \
		-L $(dir $(LIBBUILTINS)) \
		-Wl,-rpath $(dir $(LIBBUILTINS)) \
		build/spectre/module.o -lbuiltins -o $@

build/sensitivity1/module.so: build/sensitivity1/module.o
	@mkdir -p $(@D)
	$(CC) -rdynamic -shared \
		-L $(dir $(LIBBUILTINS)) \
		-Wl,-rpath $(dir $(LIBBUILTINS)) \
		build/sensitivity1/module.o -lbuiltins -o $@

build/sensitivity2/module.so: build/sensitivity2/module.o
	@mkdir -p $(@D)
	$(CC) -rdynamic -shared \
		-L $(dir $(LIBBUILTINS)) \
		-Wl,-rpath $(dir $(LIBBUILTINS)) \
		build/sensitivity2/module.o -lbuiltins -o $@

build/sensitivity3/module.so: build/sensitivity3/module.o
	@mkdir -p $(@D)
	$(CC) -rdynamic -shared \
		-L $(dir $(LIBBUILTINS)) \
		-Wl,-rpath $(dir $(LIBBUILTINS)) \
		build/sensitivity3/module.o -lbuiltins -o $@

build/sensitivity4/module.so: build/sensitivity4/module.o
	@mkdir -p $(@D)
	$(CC) -rdynamic -shared \
		-L $(dir $(LIBBUILTINS)) \
		-Wl,-rpath $(dir $(LIBBUILTINS)) \
		build/sensitivity4/module.o -lbuiltins -o $@

build/sensitivity5/module.so: build/sensitivity5/module.o
	@mkdir -p $(@D)
	$(CC) -rdynamic -shared \
		-L $(dir $(LIBBUILTINS)) \
		-Wl,-rpath $(dir $(LIBBUILTINS)) \
		build/sensitivity5/module.o -lbuiltins -o $@

build/fence/module.so: build/fence/module.o
	@mkdir -p $(@D)
	$(CC) -rdynamic -shared \
		-L $(dir $(LIBBUILTINS)) \
		-Wl,-rpath $(dir $(LIBBUILTINS)) \
		build/fence/module.o -lbuiltins -o $@

build/lucet/%.o: %.c
	@mkdir -p $(@D)
	$(CC) --std=c99 -fPIC -D_GNU_SOURCE -g3 $(COMMON_CFLAGS) \
		-fvisibility=default \
		-I$(LUCET_RUNTIME)/include \
		-I$(LUCET_WASI)/include \
		-DWASM_MODULE=$(abspath build/lucet/module.so) \
		-c $^ -o $@

build/spectre/%.o: %.c
	@mkdir -p $(@D)
	$(CC) --std=c99 -fPIC -D_GNU_SOURCE -g3 $(COMMON_CFLAGS) \
		-fvisibility=default \
		-I$(LUCET_RUNTIME)/include \
		-I$(LUCET_WASI)/include \
		-DWASM_MODULE=$(abspath build/spectre/module.so) \
		-c $^ -o $@

build/sensitivity1/%.o: %.c
	@mkdir -p $(@D)
	$(CC) --std=c99 -fPIC -D_GNU_SOURCE -g3 $(COMMON_CFLAGS) \
		-fvisibility=default \
		-I$(LUCET_RUNTIME)/include \
		-I$(LUCET_WASI)/include \
		-DWASM_MODULE=$(abspath build/sensitivity1/module.so) \
		-c $^ -o $@

build/sensitivity2/%.o: %.c
	@mkdir -p $(@D)
	$(CC) --std=c99 -fPIC -D_GNU_SOURCE -g3 $(COMMON_CFLAGS) \
		-fvisibility=default \
		-I$(LUCET_RUNTIME)/include \
		-I$(LUCET_WASI)/include \
		-DWASM_MODULE=$(abspath build/sensitivity2/module.so) \
		-c $^ -o $@

build/sensitivity3/%.o: %.c
	@mkdir -p $(@D)
	$(CC) --std=c99 -fPIC -D_GNU_SOURCE -g3 $(COMMON_CFLAGS) \
		-fvisibility=default \
		-I$(LUCET_RUNTIME)/include \
		-I$(LUCET_WASI)/include \
		-DWASM_MODULE=$(abspath build/sensitivity3/module.so) \
		-c $^ -o $@

build/sensitivity4/%.o: %.c
	@mkdir -p $(@D)
	$(CC) --std=c99 -fPIC -D_GNU_SOURCE -g3 $(COMMON_CFLAGS) \
		-fvisibility=default \
		-I$(LUCET_RUNTIME)/include \
		-I$(LUCET_WASI)/include \
		-DWASM_MODULE=$(abspath build/sensitivity4/module.so) \
		-c $^ -o $@

build/sensitivity5/%.o: %.c
	@mkdir -p $(@D)
	$(CC) --std=c99 -fPIC -D_GNU_SOURCE -g3 $(COMMON_CFLAGS) \
		-fvisibility=default \
		-I$(LUCET_RUNTIME)/include \
		-I$(LUCET_WASI)/include \
		-DWASM_MODULE=$(abspath build/sensitivity5/module.so) \
		-c $^ -o $@

build/fence/%.o: %.c
	@mkdir -p $(@D)
	$(CC) --std=c99 -fPIC -D_GNU_SOURCE -g3 $(COMMON_CFLAGS) \
		-fvisibility=default \
		-I$(LUCET_RUNTIME)/include \
		-I$(LUCET_WASI)/include \
		-DWASM_MODULE=$(abspath build/fence/module.so) \
		-c $^ -o $@

build/lucet/implementation.so: $(LUCET_ROOT)/target/release/liblucet_runtime.so
build/lucet/implementation.so: $(LUCET_ROOT)/target/release/liblucet_wasi.so
build/lucet/implementation.so: build/lucet/wrapper.o
build/lucet/implementation.so: build/lucet/hostcalls.o
build/lucet/implementation.so: $(LIBBUILTINS)
	@mkdir -p $(@D)
	$(CC) -rdynamic -shared \
		-L $(dir $(LIBBUILTINS)) \
		-Wl,-rpath $(dir $(LIBBUILTINS)) \
		build/lucet/wrapper.o build/lucet/hostcalls.o \
		-L $(LUCET_ROOT)/target/release \
		-Wl,-rpath $(LUCET_ROOT)/target/release \
		-llucet_runtime -llucet_wasi -ldl -lbuiltins -o $@


build/spectre/implementation.so: $(LUCET_ROOT)/target/release/liblucet_runtime.so
build/spectre/implementation.so: $(LUCET_ROOT)/target/release/liblucet_wasi.so
build/spectre/implementation.so: build/spectre/wrapper.o
build/spectre/implementation.so: build/spectre/hostcalls.o
build/spectre/implementation.so: $(LIBBUILTINS)
	@mkdir -p $(@D)
	$(CC) -rdynamic -shared \
		-L $(dir $(LIBBUILTINS)) \
		-Wl,-rpath $(dir $(LIBBUILTINS)) \
		build/spectre/wrapper.o build/spectre/hostcalls.o \
		-L $(LUCET_ROOT)/target/release \
		-Wl,-rpath $(LUCET_ROOT)/target/release \
		-llucet_runtime -llucet_wasi -ldl -lbuiltins -o $@

build/sensitivity1/implementation.so: $(addsuffix /wrapper.o, $(addprefix build/sensitivity, $(SENSIVITYRANGE) ))
build/sensitivity1/implementation.so: $(addsuffix /hostcalls.o, $(addprefix build/sensitivity, $(SENSIVITYRANGE) ))

build/sensitivity1/implementation.so: $(LIBBUILTINS)
	@mkdir -p $(@D)
	$(CC) -rdynamic -shared \
		-L $(dir $(LIBBUILTINS)) \
		-Wl,-rpath $(dir $(LIBBUILTINS)) \
		build/sensitivity1/wrapper.o build/sensitivity1/hostcalls.o \
		-L $(LUCET_ROOT)/target/release \
		-Wl,-rpath $(LUCET_ROOT)/target/release \
		-llucet_runtime -llucet_wasi -ldl -lbuiltins -o $@

build/sensitivity2/implementation.so: $(LIBBUILTINS)
	@mkdir -p $(@D)
	$(CC) -rdynamic -shared \
		-L $(dir $(LIBBUILTINS)) \
		-Wl,-rpath $(dir $(LIBBUILTINS)) \
		build/sensitivity2/wrapper.o build/sensitivity2/hostcalls.o \
		-L $(LUCET_ROOT)/target/release \
		-Wl,-rpath $(LUCET_ROOT)/target/release \
		-llucet_runtime -llucet_wasi -ldl -lbuiltins -o $@

build/sensitivity3/implementation.so: $(LIBBUILTINS)
	@mkdir -p $(@D)
	$(CC) -rdynamic -shared \
		-L $(dir $(LIBBUILTINS)) \
		-Wl,-rpath $(dir $(LIBBUILTINS)) \
		build/sensitivity3/wrapper.o build/sensitivity3/hostcalls.o \
		-L $(LUCET_ROOT)/target/release \
		-Wl,-rpath $(LUCET_ROOT)/target/release \
		-llucet_runtime -llucet_wasi -ldl -lbuiltins -o $@

build/sensitivity4/implementation.so: $(LIBBUILTINS)
	@mkdir -p $(@D)
	$(CC) -rdynamic -shared \
		-L $(dir $(LIBBUILTINS)) \
		-Wl,-rpath $(dir $(LIBBUILTINS)) \
		build/sensitivity4/wrapper.o build/sensitivity4/hostcalls.o \
		-L $(LUCET_ROOT)/target/release \
		-Wl,-rpath $(LUCET_ROOT)/target/release \
		-llucet_runtime -llucet_wasi -ldl -lbuiltins -o $@

build/sensitivity5/implementation.so: $(LIBBUILTINS)
	@mkdir -p $(@D)
	$(CC) -rdynamic -shared \
		-L $(dir $(LIBBUILTINS)) \
		-Wl,-rpath $(dir $(LIBBUILTINS)) \
		build/sensitivity5/wrapper.o build/sensitivity5/hostcalls.o \
		-L $(LUCET_ROOT)/target/release \
		-Wl,-rpath $(LUCET_ROOT)/target/release \
		-llucet_runtime -llucet_wasi -ldl -lbuiltins -o $@

build/fence/implementation.so: $(LUCET_ROOT)/target/release/liblucet_runtime.so
build/fence/implementation.so: $(LUCET_ROOT)/target/release/liblucet_wasi.so
build/fence/implementation.so: build/fence/wrapper.o
build/fence/implementation.so: build/fence/hostcalls.o
build/fence/implementation.so: $(LIBBUILTINS)
	@mkdir -p $(@D)
	$(CC) -rdynamic -shared \
		-L $(dir $(LIBBUILTINS)) \
		-Wl,-rpath $(dir $(LIBBUILTINS)) \
		build/fence/wrapper.o build/fence/hostcalls.o \
		-L $(LUCET_ROOT)/target/release \
		-Wl,-rpath $(LUCET_ROOT)/target/release \
		-llucet_runtime -llucet_wasi -ldl -lbuiltins -o $@

$(LUCET_ROOT)/target/release/sightglass:
	cargo build --release -p sightglass

$(LIBBUILTINS):
	make -C $(LUCET_ROOT)/lucet-builtins

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
