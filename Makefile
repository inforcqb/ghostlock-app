API ?= 35

# Auto-detect NDK
ifeq ($(OS),Windows_NT)
  NDK_ROOT ?= $(subst \,/,$(firstword $(wildcard     $(subst \,/,$(LOCALAPPDATA))/Android/Sdk/ndk/*     $(subst \,/,$(ANDROID_HOME))/ndk/*     D:/AndroidSDK/ndk/*)))
  override NDK_ROOT := $(subst \,/,$(NDK_ROOT))
  PREBUILT := windows-x86_64
  CLANG_BASE := aarch64-linux-android$(API)-clang
  CLANGXX_BASE := aarch64-linux-android$(API)-clang++
  NDK_CC := $(NDK_ROOT)/toolchains/llvm/prebuilt/$(PREBUILT)/bin/$(CLANG_BASE).cmd
  NDK_CXX := $(NDK_ROOT)/toolchains/llvm/prebuilt/$(PREBUILT)/bin/$(CLANGXX_BASE).cmd
else
  NDK_ROOT ?= $(or $(ANDROID_NDK_HOME),$(ANDROID_NDK_ROOT))
  UNAME_S := $(shell uname -s)
  PREBUILT := $(if $(filter Darwin,$(UNAME_S)),darwin-x86_64,linux-x86_64)
  NDK_CC := $(NDK_ROOT)/toolchains/llvm/prebuilt/$(PREBUILT)/bin/aarch64-linux-android$(API)-clang
  NDK_CXX := $(NDK_ROOT)/toolchains/llvm/prebuilt/$(PREBUILT)/bin/aarch64-linux-android$(API)-clang++
endif

# Used only by the JNI library target below, to check that the .so does not end up
# depending on libc++_shared.so (which the APK does not ship).
LLVM_READELF := $(NDK_ROOT)/toolchains/llvm/prebuilt/$(PREBUILT)/bin/llvm-readelf

C_SRCS :=

CXX_SRCS := \
  src/core/main.cpp \
  src/core/exploit_ops.cpp \
  src/core/memory/address_space.cpp \
  src/core/memory/heap_context.cpp \
  src/core/pi_race.cpp \
  src/core/pipe_daemon.cpp \
  src/core/routes/route_controller.cpp \
  src/core/routes/route_threads.cpp \
  src/core/routes/tcp_zerocopy_route.cpp \
  src/core/routes/select_stack_route.cpp \
  src/core/routes/multicast_waiter_route.cpp \
  src/core/memory/payload_builder.cpp \
  src/core/session/runtime_config.cpp \
  src/core/offsets_json.cpp \
  src/core/profile_binary.cpp \
  src/core/util.cpp \
  src/core/routes/route_operations.cpp \
  src/core/session/exploit_session.cpp \
  src/core/session/exploit_stages.cpp \
  src/core/session/handoff_probe.cpp \
  src/core/session/victim_process.cpp \
  src/core/session/victim_context.cpp \
  src/core/support/native_resource.cpp

NATIVE_BUILD_DIR := .build/native
C_OBJS := $(patsubst %.c,$(NATIVE_BUILD_DIR)/%.o,$(C_SRCS))
CXX_OBJS := $(patsubst %.cpp,$(NATIVE_BUILD_DIR)/%.o,$(CXX_SRCS))
OBJS := $(C_OBJS) $(CXX_OBJS)

# Native interface and target headers also trigger a rebuild.
HDRS := $(wildcard src/core/*.h src/core/*.hpp src/core/*/*.h src/core/*/*.hpp)

# Device offsets are selected at runtime from uname -r.
TARGET_CONFIG ?= target.h

COMMON_FLAGS := -O2 -flto -Wall -Wextra -Wconversion -Wsign-conversion \
  -Wno-unused-parameter -Wno-sign-compare -Wno-unused-function \
  -Isrc/core -DTARGET_CONFIG_H=\"$(TARGET_CONFIG)\"
CFLAGS := $(COMMON_FLAGS) -std=gnu11
CXXFLAGS := $(COMMON_FLAGS) -std=c++20 -fno-rtti
LDFLAGS := -fPIE -pie -pthread -flto -static-libstdc++

HOST_CC ?= cc
HOST_CXX ?= c++
HOST_CXXFLAGS := -std=c++20 -fno-rtti -Wall -Wextra -Wconversion -Wsign-conversion
HOST_BUILD_DIR := .build/host

.PHONY: all clean product

all: ghostlock

ghostlock: $(OBJS) Makefile
	@echo "Using NDK compiler: $(NDK_CC)"
	@echo "Using NDK C++ compiler/linker: $(NDK_CXX)"
	@echo "Target config: $(TARGET_CONFIG)"
	$(NDK_CXX) $(OBJS) $(LDFLAGS) -o ghostlock

$(NATIVE_BUILD_DIR)/%.o: %.c $(HDRS)
	@mkdir -p $(dir $@)
	$(NDK_CC) $(CFLAGS) -c $< -o $@

$(NATIVE_BUILD_DIR)/%.o: %.cpp $(HDRS)
	@mkdir -p $(dir $@)
	$(NDK_CXX) $(CXXFLAGS) -c $< -o $@

# ---------------------------------------------------------------------------
# libmagica2.so -- the ported Magica root-shell JNI library (app/src/main/jni).
#
# Build wiring: option (b) of the port brief.  This target produces the shared
# library with the same NDK clang++ that already builds the app's own binary, and
# the root Gradle task `prepareMagica2JniLibs` copies `.build/jni/libmagica2.so`
# into app/build/generated/magica2JniLibs/arm64-v8a/, which app/build.gradle.kts
# registers as an extra jniLibs source directory.  AGP's externalNativeBuild is
# deliberately NOT used: CI's NDK is ONDK (NDK_ROOT/ANDROID_NDK_HOME), which AGP
# cannot resolve, and ndk-build here would additionally pull prefab plus the
# org.lsposed.libcxx:libcxx dependency.
#
# NOTE: the executable LDFLAGS above (-fPIE -pie) must NOT be reused here -- this
# is a shared library, so it is -fPIC/-shared.  -static-libstdc++ IS reused and is
# load-bearing: it makes the driver link libc++_static instead of libc++, so the
# .so does not end up needing libc++_shared.so, which the APK does not ship
# (upstream reached the same place with prefab's `cxx` and APP_STL := none).
# ---------------------------------------------------------------------------
JNI_DIR := app/src/main/jni
JNI_BUILD_DIR := .build/jni
JNI_SRCS := \
  magica.cpp \
  lsplt/elf_util.cc \
  lsplt/lsplt.cc \
  system_properties/context_node.cpp \
  system_properties/contexts_serialized.cpp \
  system_properties/contexts_split.cpp \
  system_properties/prop_area.cpp \
  system_properties/prop_info.cpp \
  system_properties/property_info_parser.cpp \
  system_properties/system_properties.cpp \
  system_properties/system_property_api.cpp \
  system_properties/system_property_set.cpp
JNI_OBJS := $(addprefix $(JNI_BUILD_DIR)/,$(patsubst %.cpp,%.o,$(patsubst %.cc,%.o,$(JNI_SRCS))))
JNI_HDRS := $(wildcard $(JNI_DIR)/*.h $(JNI_DIR)/*.hpp $(JNI_DIR)/*/*.h $(JNI_DIR)/*/*.hpp)

# -fvisibility=hidden / -fvisibility-inlines-hidden are functional, not cosmetic:
# they keep the vendored resetprop (and the statically linked libc++) inside the
# shared object instead of exporting -- or being interposed by -- libc's own
# __system_property_* (same flags as upstream's Application.mk).
JNI_CFLAGS := -O2 -fPIC -fvisibility=hidden -fvisibility-inlines-hidden \
  -Wall -Wextra -Wno-unused-parameter -Wno-unused-function \
  -std=c++23 -pthread \
  -I$(JNI_DIR) \
  -I$(JNI_DIR)/lsplt/include \
  -I$(JNI_DIR)/system_properties/include

JNI_LDFLAGS := -shared -static-libstdc++ -Wl,-soname,libmagica2.so \
  -Wl,-exclude-libs,ALL -Wl,--gc-sections

.PHONY: magica2jni
magica2jni: $(JNI_BUILD_DIR)/libmagica2.so

$(JNI_BUILD_DIR)/libmagica2.so: $(JNI_OBJS) Makefile
	@echo "Using NDK C++ compiler/linker: $(NDK_CXX)"
	$(NDK_CXX) $(JNI_OBJS) $(JNI_LDFLAGS) -llog -o $@
	@if [ -x "$(LLVM_READELF)" ]; then \
		if "$(LLVM_READELF)" -d $@ 2>/dev/null | grep -q libc++_shared; then \
			echo "WARNING: $@ needs libc++_shared.so, which the APK does not ship"; \
			"$(LLVM_READELF)" -d $@ | grep NEEDED; \
		else \
			echo "OK: $@ needs no libc++_shared.so"; \
		fi; \
	fi

$(JNI_BUILD_DIR)/%.o: $(JNI_DIR)/%.cpp $(JNI_HDRS)
	@mkdir -p $(dir $@)
	$(NDK_CXX) $(JNI_CFLAGS) -c $< -o $@

$(JNI_BUILD_DIR)/%.o: $(JNI_DIR)/%.cc $(JNI_HDRS)
	@mkdir -p $(dir $@)
	$(NDK_CXX) $(JNI_CFLAGS) -c $< -o $@

.PHONY: cpp-link-probe-test target-constants-test native-resource-test native-host-tests lint-tidy
cpp-link-probe-test: $(HOST_BUILD_DIR)/cpp_link_probe_test
	$(HOST_BUILD_DIR)/cpp_link_probe_test

target-constants-test: $(HOST_BUILD_DIR)/target_constants_test
	$(HOST_BUILD_DIR)/target_constants_test

native-resource-test: $(HOST_BUILD_DIR)/native_resource_test
	$(HOST_BUILD_DIR)/native_resource_test

NATIVE_HOST_TESTS := \
  profile_test payload_builder_test heap_context_test route_status_test \
  runtime_time_test \
  kernelsnitch_scan_bounds_test route_controller_test pi_race_test \
  tcp_zerocopy_route_test select_stack_route_test \
  multicast_waiter_route_test target_constants_test native_resource_test \
  offsets_json_test profile_binary_test futex_hash_test number_parse_test \
  runtime_paths_test handoff_probe_test victim_context_test

native-host-tests: $(addprefix $(HOST_BUILD_DIR)/,$(NATIVE_HOST_TESTS))
	@status=0; for test in $^; do $$test || status=1; done; exit $$status

# Host tests must rebuild whenever any production header changes.
$(addprefix $(HOST_BUILD_DIR)/,$(NATIVE_HOST_TESTS)): $(HDRS)

# CPP14 selected clang-tidy subset; the check list and its reviewed
# exclusions live in .clang-tidy. Requires the NDK so the Android and
# libc++ headers resolve.
lint-tidy:
	@test -n "$(NDK_ROOT)" || { echo "NDK_ROOT is not set"; exit 1; }
	@status=0; for f in $(CXX_SRCS); do \
	  $(NDK_ROOT)/toolchains/llvm/prebuilt/$(PREBUILT)/bin/clang-tidy "$$f" \
	    --warnings-as-errors='*' -- \
	    -std=c++20 -fno-rtti -Isrc/core \
	    --target=aarch64-linux-android$(API) \
	    --sysroot=$(NDK_ROOT)/toolchains/llvm/prebuilt/$(PREBUILT)/sysroot \
	    -DTARGET_CONFIG_H=\"$(TARGET_CONFIG)\" || status=1; \
	done; exit $$status

$(HOST_BUILD_DIR)/cpp_link_probe_test: src/core/tests/cpp_link_probe.cpp src/core/tests/cpp_link_probe.h src/core/tests/cpp_link_probe_test.c
	@mkdir -p $(HOST_BUILD_DIR)
	$(HOST_CC) -std=c11 -Isrc/core -c src/core/tests/cpp_link_probe_test.c -o $(HOST_BUILD_DIR)/cpp_link_probe_test.o
	$(HOST_CXX) $(HOST_CXXFLAGS) -Isrc/core -c src/core/tests/cpp_link_probe.cpp -o $(HOST_BUILD_DIR)/cpp_link_probe.o
	$(HOST_CXX) $(HOST_BUILD_DIR)/cpp_link_probe_test.o $(HOST_BUILD_DIR)/cpp_link_probe.o -o $@

$(HOST_BUILD_DIR)/target_constants_test: src/core/tests/target_constants_test.cpp src/core/target.h src/core/target_constants.hpp
	@mkdir -p $(HOST_BUILD_DIR)
	$(HOST_CXX) $(HOST_CXXFLAGS) -Isrc/core src/core/tests/target_constants_test.cpp -o $@

$(HOST_BUILD_DIR)/native_resource_test: src/core/tests/native_resource_test.cpp src/core/support/native_resource.cpp src/core/support/native_resource.hpp src/core/support/native_result.hpp
	@mkdir -p $(HOST_BUILD_DIR)
	$(HOST_CXX) $(HOST_CXXFLAGS) -pthread -Isrc/core src/core/tests/native_resource_test.cpp src/core/support/native_resource.cpp -o $@

$(HOST_BUILD_DIR)/route_status_test: src/core/tests/route_status_test.cpp src/core/routes/route_status.h
	@mkdir -p $(HOST_BUILD_DIR)
	$(HOST_CXX) $(HOST_CXXFLAGS) -Isrc/core $< -o $@

$(HOST_BUILD_DIR)/runtime_time_test: src/core/tests/runtime_time_test.cpp src/core/runtime_time.h
	@mkdir -p $(HOST_BUILD_DIR)
	$(HOST_CXX) $(HOST_CXXFLAGS) -Isrc/core $< -o $@

$(HOST_BUILD_DIR)/profile_test: src/core/tests/profile_test.cpp src/core/profile.h
	@mkdir -p $(HOST_BUILD_DIR)
	$(HOST_CXX) $(HOST_CXXFLAGS) -Isrc/core $< -o $@

$(HOST_BUILD_DIR)/profile_binary_test: src/core/tests/profile_binary_test.cpp src/core/profile_binary.cpp src/core/profile_binary.h src/core/profile.h
	$(HOST_CXX) $(HOST_CXXFLAGS) -Isrc/core src/core/tests/profile_binary_test.cpp src/core/profile_binary.cpp -o $@

$(HOST_BUILD_DIR)/payload_builder_test: src/core/tests/payload_builder_test.cpp src/core/memory/payload_builder.cpp src/core/memory/payload_builder.h
	@mkdir -p $(HOST_BUILD_DIR)
	$(HOST_CXX) $(HOST_CXXFLAGS) -Isrc/core src/core/tests/payload_builder_test.cpp src/core/memory/payload_builder.cpp -o $@

$(HOST_BUILD_DIR)/heap_context_test: src/core/tests/heap_context_test.cpp src/core/memory/heap_context.cpp src/core/memory/heap_context.h src/core/support/native_resource.cpp src/core/support/native_resource.hpp
	@mkdir -p $(HOST_BUILD_DIR)
	$(HOST_CXX) $(HOST_CXXFLAGS) -Isrc/core src/core/tests/heap_context_test.cpp src/core/memory/heap_context.cpp src/core/support/native_resource.cpp -o $@

$(HOST_BUILD_DIR)/kernelsnitch_scan_bounds_test: src/core/tests/kernelsnitch_scan_bounds_test.cpp src/core/kernelsnitch/scan_bounds.h
	@mkdir -p $(HOST_BUILD_DIR)
	$(HOST_CXX) $(HOST_CXXFLAGS) -Isrc/core $< -o $@

$(HOST_BUILD_DIR)/route_controller_test: src/core/tests/route_controller_test.cpp src/core/routes/route_controller.cpp src/core/support/native_resource.cpp src/core/support/native_resource.hpp
	@mkdir -p $(HOST_BUILD_DIR)
	$(HOST_CXX) $(HOST_CXXFLAGS) -ffunction-sections -fdata-sections -Wl,-dead_strip -pthread -Isrc/core src/core/tests/route_controller_test.cpp src/core/routes/route_controller.cpp src/core/support/native_resource.cpp -o $@

$(HOST_BUILD_DIR)/pi_race_test: src/core/tests/pi_race_test.cpp src/core/pi_race.cpp src/core/pi_race.h src/core/support/native_resource.cpp src/core/support/native_resource.hpp
	@mkdir -p $(HOST_BUILD_DIR)
	$(HOST_CXX) $(HOST_CXXFLAGS) -pthread -Isrc/core src/core/tests/pi_race_test.cpp src/core/pi_race.cpp src/core/support/native_resource.cpp -o $@

$(HOST_BUILD_DIR)/tcp_zerocopy_route_test: src/core/tests/tcp_zerocopy_route_test.cpp src/core/routes/tcp_zerocopy_route.cpp src/core/routes/tcp_zerocopy_route.h src/core/pi_race.cpp src/core/support/native_resource.cpp src/core/support/native_resource.hpp
	@mkdir -p $(HOST_BUILD_DIR)
	$(HOST_CXX) $(HOST_CXXFLAGS) -pthread -Isrc/core src/core/tests/tcp_zerocopy_route_test.cpp src/core/routes/tcp_zerocopy_route.cpp src/core/pi_race.cpp src/core/support/native_resource.cpp -o $@

$(HOST_BUILD_DIR)/select_stack_route_test: src/core/tests/select_stack_route_test.cpp src/core/routes/select_stack_route.cpp src/core/routes/select_stack_route.h src/core/pi_race.cpp src/core/support/native_resource.cpp src/core/support/native_resource.hpp
	@mkdir -p $(HOST_BUILD_DIR)
	$(HOST_CXX) $(HOST_CXXFLAGS) -pthread -Isrc/core src/core/tests/select_stack_route_test.cpp src/core/routes/select_stack_route.cpp src/core/pi_race.cpp src/core/support/native_resource.cpp -o $@

$(HOST_BUILD_DIR)/multicast_waiter_route_test: src/core/tests/multicast_waiter_route_test.cpp src/core/support/native_resource.cpp src/core/support/native_resource.hpp
	@mkdir -p $(HOST_BUILD_DIR)
	$(HOST_CXX) $(HOST_CXXFLAGS) -pthread -Isrc/core src/core/tests/multicast_waiter_route_test.cpp src/core/support/native_resource.cpp -o $@

$(HOST_BUILD_DIR)/offsets_json_test: src/core/tests/offsets_json_test.cpp src/core/offsets_json.cpp src/core/memory/address_space.cpp src/core/support/native_resource.cpp
	@mkdir -p $(HOST_BUILD_DIR)
	$(HOST_CXX) $(HOST_CXXFLAGS) -Isrc/core src/core/tests/offsets_json_test.cpp src/core/offsets_json.cpp src/core/profile_binary.cpp src/core/memory/address_space.cpp src/core/support/native_resource.cpp -o $@

$(HOST_BUILD_DIR)/futex_hash_test: src/core/tests/futex_hash_test.cpp src/core/kernelsnitch/futex_hash.h
	@mkdir -p $(HOST_BUILD_DIR)
	$(HOST_CXX) $(HOST_CXXFLAGS) -Isrc/core $< -o $@

$(HOST_BUILD_DIR)/number_parse_test: src/core/tests/number_parse_test.cpp src/core/kernelsnitch/number_parse.h
	@mkdir -p $(HOST_BUILD_DIR)
	$(HOST_CXX) $(HOST_CXXFLAGS) -Isrc/core $< -o $@

$(HOST_BUILD_DIR)/runtime_paths_test: src/core/tests/runtime_paths_test.cpp src/core/session/runtime_paths.h
	@mkdir -p $(HOST_BUILD_DIR)
	$(HOST_CXX) $(HOST_CXXFLAGS) -Isrc/core $< -o $@

$(HOST_BUILD_DIR)/handoff_probe_test: src/core/tests/handoff_probe_test.cpp src/core/session/handoff_probe.cpp src/core/session/handoff_probe.hpp
	@mkdir -p $(HOST_BUILD_DIR)
	$(HOST_CXX) $(HOST_CXXFLAGS) -Isrc/core src/core/tests/handoff_probe_test.cpp src/core/session/handoff_probe.cpp -o $@

$(HOST_BUILD_DIR)/victim_context_test: src/core/tests/victim_context_test.cpp src/core/session/victim_context.cpp src/core/session/victim_context.hpp src/core/support/native_resource.cpp src/core/support/native_resource.hpp
	@mkdir -p $(HOST_BUILD_DIR)
	$(HOST_CXX) $(HOST_CXXFLAGS) -pthread -Isrc/core src/core/tests/victim_context_test.cpp src/core/session/victim_context.cpp src/core/support/native_resource.cpp -o $@

product: ghostlock
	@echo "=== ghostlock binary ready: ./ghostlock ==="
	@echo "构建 APK: .\gradlew.bat :app:assembleDebug"

clean:
	rm -f ghostlock
	rm -rf .build/native .build/host .build/jni
