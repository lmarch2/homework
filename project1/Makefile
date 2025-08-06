# SM4 Implementation Makefile - Redesigned for Performance Comparison

CC = gcc
CFLAGS_BASIC = -Wall -Wextra -std=c99
CFLAGS_O3 = -Wall -Wextra -O3 -std=c99  
CFLAGS_NATIVE = -Wall -Wextra -O3 -std=c99 -march=native
LDFLAGS = -lm

# Directories
SRCDIR = src
TESTDIR = tests
BENCHDIR = benchmark
BINDIR = bin

.PHONY: all clean test benchmark benchmark-all

# Default target
all: benchmark-all

# Object file compilation rules for different optimization levels
$(SRCDIR)/%_basic.o: $(SRCDIR)/%.c
	$(CC) $(CFLAGS_BASIC) -c -o $@ $<

$(SRCDIR)/%_o3.o: $(SRCDIR)/%.c
	$(CC) $(CFLAGS_O3) -c -o $@ $<

$(SRCDIR)/%_native.o: $(SRCDIR)/%.c
	$(CC) $(CFLAGS_NATIVE) -c -o $@ $<

$(SRCDIR)/sm4_aesni_native.o: $(SRCDIR)/sm4_aesni.c
	$(CC) $(CFLAGS_NATIVE) -maes -mpclmul -c -o $@ $<

$(SRCDIR)/sm4_gfni_native.o: $(SRCDIR)/sm4_gfni.c
	$(CC) $(CFLAGS_NATIVE) -mgfni -mavx2 -mavx512f -c -o $@ $<

$(TESTDIR)/%_basic.o: $(TESTDIR)/%.c
	$(CC) $(CFLAGS_BASIC) -c -o $@ $<

$(TESTDIR)/%_o3.o: $(TESTDIR)/%.c
	$(CC) $(CFLAGS_O3) -c -o $@ $<

$(TESTDIR)/%_native.o: $(TESTDIR)/%.c
	$(CC) $(CFLAGS_NATIVE) -c -o $@ $<

# Test executables for each implementation
$(BINDIR)/test_basic: $(SRCDIR)/sm4_basic_basic.o $(TESTDIR)/test_unified_basic.o
	@mkdir -p $(BINDIR)
	$(CC) $(CFLAGS_BASIC) -o $@ $^ $(LDFLAGS)

$(BINDIR)/test_o3: $(SRCDIR)/sm4_basic_o3.o $(TESTDIR)/test_unified_o3.o
	@mkdir -p $(BINDIR)
	$(CC) $(CFLAGS_O3) -o $@ $^ $(LDFLAGS)

$(BINDIR)/test_native: $(SRCDIR)/sm4_basic_native.o $(TESTDIR)/test_unified_native.o
	@mkdir -p $(BINDIR)
	$(CC) $(CFLAGS_NATIVE) -o $@ $^ $(LDFLAGS)

# Special compilation for T-table test with macro
$(TESTDIR)/test_unified_ttable.o: $(TESTDIR)/test_unified.c
	$(CC) $(CFLAGS_NATIVE) -DTESTING_TTABLE -c -o $@ $<

$(BINDIR)/test_ttable: $(SRCDIR)/sm4_ttable_native.o $(SRCDIR)/sm4_basic_native.o $(TESTDIR)/test_unified_ttable.o
	@mkdir -p $(BINDIR)
	$(CC) $(CFLAGS_NATIVE) -o $@ $^ $(LDFLAGS)

# Special compilation for AES-NI test with macro
$(TESTDIR)/test_unified_aesni.o: $(TESTDIR)/test_unified.c
	$(CC) $(CFLAGS_NATIVE) -DTESTING_AESNI -c -o $@ $<

$(BINDIR)/test_aesni: $(SRCDIR)/sm4_aesni_native.o $(SRCDIR)/sm4_basic_native.o $(SRCDIR)/cpu_detect_native.o $(TESTDIR)/test_unified_aesni.o
	@mkdir -p $(BINDIR)
	$(CC) $(CFLAGS_NATIVE) -maes -mpclmul -o $@ $^ $(LDFLAGS)

# Special compilation for GFNI test with macro
$(TESTDIR)/test_unified_gfni.o: $(TESTDIR)/test_unified.c
	$(CC) $(CFLAGS_NATIVE) -DTESTING_GFNI -c -o $@ $<

$(BINDIR)/test_gfni: $(SRCDIR)/sm4_gfni_native.o $(SRCDIR)/sm4_basic_native.o $(SRCDIR)/cpu_detect_native.o $(TESTDIR)/test_unified_gfni.o
	@mkdir -p $(BINDIR)
	$(CC) $(CFLAGS_NATIVE) -mgfni -mavx2 -mavx512f -o $@ $^ $(LDFLAGS)

# Comprehensive test suite
$(BINDIR)/test_comprehensive: $(SRCDIR)/sm4_basic_native.o $(SRCDIR)/sm4_ttable_native.o $(SRCDIR)/sm4_aesni_native.o $(SRCDIR)/sm4_gfni_native.o $(SRCDIR)/sm4_gcm_native.o $(SRCDIR)/utils_native.o $(SRCDIR)/cpu_detect_native.o $(TESTDIR)/test_sm4_native.o
	@mkdir -p $(BINDIR)
	$(CC) $(CFLAGS_NATIVE) -maes -mpclmul -mgfni -mavx2 -mavx512f -o $@ $^ $(LDFLAGS)

# GCM performance test
$(BINDIR)/test_gcm_perf: $(SRCDIR)/sm4_basic_native.o $(SRCDIR)/sm4_gcm_native.o $(TESTDIR)/test_gcm_performance_native.o
	@mkdir -p $(BINDIR)
	$(CC) $(CFLAGS_NATIVE) -o $@ $^ $(LDFLAGS)

$(SRCDIR)/sm4_gcm_native.o: $(SRCDIR)/sm4_gcm.c
	$(CC) $(CFLAGS_NATIVE) -c -o $@ $<

$(SRCDIR)/utils_native.o: $(SRCDIR)/utils.c
	$(CC) $(CFLAGS_NATIVE) -c -o $@ $<

$(TESTDIR)/test_sm4_native.o: $(TESTDIR)/test_sm4.c
	$(CC) $(CFLAGS_NATIVE) -c -o $@ $<

$(TESTDIR)/test_gcm_performance_native.o: $(TESTDIR)/test_gcm_performance.c
	$(CC) $(CFLAGS_NATIVE) -c -o $@ $<

# Comprehensive benchmark
benchmark-all: $(BINDIR)/test_basic $(BINDIR)/test_o3 $(BINDIR)/test_native $(BINDIR)/test_ttable $(BINDIR)/test_aesni $(BINDIR)/test_gfni
	@echo "=== SM4 Performance Comparison (vs Basic Implementation) ==="
	@echo ""
	@echo "Running Basic implementation (no optimization - baseline)..."
	@$(BINDIR)/test_basic | grep "Performance:" | awk '{print $$2}' | sed 's/MB\/s//' > /tmp/basic_result
	@BASIC_PERF=$$(cat /tmp/basic_result) && \
	echo "Basic (gcc):           $${BASIC_PERF} MB/s (1.00x baseline)" && \
	echo "" && \
	echo "Running compiler optimizations..." && \
	O3_PERF=$$($(BINDIR)/test_o3 | grep "Performance:" | awk '{print $$2}' | sed 's/MB\/s//') && \
	O3_RATIO=$$(echo "scale=2; $$O3_PERF / $$BASIC_PERF" | bc) && \
	echo "O3 optimization:       $${O3_PERF} MB/s ($${O3_RATIO}x)" && \
	NATIVE_PERF=$$($(BINDIR)/test_native | grep "Performance:" | awk '{print $$2}' | sed 's/MB\/s//') && \
	NATIVE_RATIO=$$(echo "scale=2; $$NATIVE_PERF / $$BASIC_PERF" | bc) && \
	echo "O3 + march=native:     $${NATIVE_PERF} MB/s ($${NATIVE_RATIO}x)" && \
	echo "" && \
	echo "Running algorithm optimizations..." && \
	TTABLE_PERF=$$($(BINDIR)/test_ttable | grep "Performance:" | awk '{print $$2}' | sed 's/MB\/s//') && \
	TTABLE_RATIO=$$(echo "scale=2; $$TTABLE_PERF / $$BASIC_PERF" | bc) && \
	echo "T-table optimization:  $${TTABLE_PERF} MB/s ($${TTABLE_RATIO}x)" && \
	AESNI_PERF=$$($(BINDIR)/test_aesni | grep "Performance:" | awk '{print $$2}' | sed 's/MB\/s//') && \
	AESNI_RATIO=$$(echo "scale=2; $$AESNI_PERF / $$BASIC_PERF" | bc) && \
	echo "AES-NI optimization:   $${AESNI_PERF} MB/s ($${AESNI_RATIO}x)" && \
	GFNI_PERF=$$($(BINDIR)/test_gfni | grep "Performance:" | awk '{print $$2}' | sed 's/MB\/s//') && \
	GFNI_RATIO=$$(echo "scale=2; $$GFNI_PERF / $$BASIC_PERF" | bc) && \
	echo "GFNI optimization:     $${GFNI_PERF} MB/s ($${GFNI_RATIO}x)" && \
	echo "" && \
	echo "Note: All optimizations compared against Basic (no compiler optimization)"

# Individual tests
test-basic: $(BINDIR)/test_basic
	@echo "Testing Basic implementation (no optimization)..."
	$(BINDIR)/test_basic

test-o3: $(BINDIR)/test_o3
	@echo "Testing O3 optimized implementation..."
	$(BINDIR)/test_o3

test-native: $(BINDIR)/test_native
	@echo "Testing native optimized implementation..."
	$(BINDIR)/test_native

test-ttable: $(BINDIR)/test_ttable
	@echo "Testing T-table implementation..."
	$(BINDIR)/test_ttable

test-aesni: $(BINDIR)/test_aesni
	@echo "Testing AES-NI implementation..."
	$(BINDIR)/test_aesni

test-gfni: $(BINDIR)/test_gfni
	@echo "Testing GFNI implementation..."
	$(BINDIR)/test_gfni

# Comprehensive test including GCM
test-comprehensive: $(BINDIR)/test_comprehensive
	@echo "Running comprehensive SM4 test suite (including GCM)..."
	$(BINDIR)/test_comprehensive

# GCM performance test
test-gcm-perf: $(BINDIR)/test_gcm_perf
	@echo "Testing SM4-GCM performance..."
	$(BINDIR)/test_gcm_perf

# GCM comparison test (basic vs optimized)
test-gcm-comparison: $(BINDIR)/test_gcm_comparison
	@echo "Testing SM4-GCM performance comparison..."
	$(BINDIR)/test_gcm_comparison

# GCM T-table optimized test
test-gcm-ttable: $(BINDIR)/test_gcm_ttable
	@echo "Testing SM4-GCM T-table optimized performance..."
	$(BINDIR)/test_gcm_ttable

$(BINDIR)/test_gcm_ttable: $(SRCDIR)/sm4_basic_native.o $(SRCDIR)/sm4_gcm_native.o $(SRCDIR)/sm4_ttable_native.o $(TESTDIR)/test_gcm_ttable_native.o
	@mkdir -p $(BINDIR)
	$(CC) $(CFLAGS_NATIVE) -o $@ $^ $(LDFLAGS)

$(TESTDIR)/test_gcm_ttable_native.o: $(TESTDIR)/test_gcm_ttable.c
	$(CC) $(CFLAGS_NATIVE) -c -o $@ $<

$(BINDIR)/test_gcm_comparison: $(SRCDIR)/sm4_basic_native.o $(SRCDIR)/sm4_gcm_native.o $(SRCDIR)/sm4_gcm_optimized_native.o $(TESTDIR)/test_gcm_comparison_native.o
	@mkdir -p $(BINDIR)
	$(CC) $(CFLAGS_NATIVE) -o $@ $^ $(LDFLAGS)

$(TESTDIR)/test_gcm_comparison_native.o: $(TESTDIR)/test_gcm_comparison.c
	$(CC) $(CFLAGS_NATIVE) -c -o $@ $<

$(SRCDIR)/sm4_gcm_optimized_native.o: $(SRCDIR)/sm4_gcm_optimized.c
	$(CC) $(CFLAGS_NATIVE) -c -o $@ $<

# Quick test
quick-test: $(BINDIR)/test_basic
	@echo "Quick correctness test..."
	$(BINDIR)/test_basic | head -10

# Clean
clean:
	rm -f $(SRCDIR)/*.o $(TESTDIR)/*.o $(BENCHDIR)/*.o
	rm -rf $(BINDIR)
	rm -f /tmp/basic_result

# Help
help:
	@echo "SM4 Performance Comparison Makefile"
	@echo ""
	@echo "Targets:"
	@echo "  all / benchmark-all  - Run comprehensive performance comparison"
	@echo "  test-basic          - Test basic implementation (baseline)"
	@echo "  test-o3             - Test O3 optimized implementation"
	@echo "  test-native         - Test native optimized implementation"
	@echo "  test-ttable         - Test T-table implementation"
	@echo "  test-aesni          - Test AES-NI implementation"
	@echo "  test-gfni           - Test GFNI implementation"
	@echo "  test-comprehensive  - Run comprehensive test suite (including GCM)"
	@echo "  test-gcm-perf       - Test SM4-GCM performance"
	@echo "  test-gcm-comparison - Compare basic vs optimized GCM performance"
	@echo "  test-gcm-ttable     - Test T-table optimized GCM performance"
	@echo "  quick-test          - Quick correctness test"
	@echo "  clean               - Clean build files"
