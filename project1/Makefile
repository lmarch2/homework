# SM4 Implementation Makefile

CC = gcc
CFLAGS = -Wall -Wextra -O3 -std=c99 -march=native
CFLAGS_DEBUG = -Wall -Wextra -g -std=c99 -DDEBUG
LDFLAGS = -lm

# Source directories
SRCDIR = src
TESTDIR = tests
BENCHDIR = benchmark

# Object files
BASIC_OBJS = $(SRCDIR)/sm4_basic.o $(SRCDIR)/utils.o $(SRCDIR)/cpu_detect.o
TTABLE_OBJS = $(SRCDIR)/sm4_ttable.o $(SRCDIR)/utils.o $(SRCDIR)/cpu_detect.o
AESNI_OBJS = $(SRCDIR)/sm4_aesni.o $(SRCDIR)/utils.o $(SRCDIR)/cpu_detect.o
GFNI_OBJS = $(SRCDIR)/sm4_gfni.o $(SRCDIR)/utils.o $(SRCDIR)/cpu_detect.o
GCM_OBJS = $(SRCDIR)/sm4_gcm.o $(SRCDIR)/utils.o $(SRCDIR)/cpu_detect.o
ALL_OBJS = $(SRCDIR)/sm4_basic.o $(SRCDIR)/sm4_ttable.o $(SRCDIR)/sm4_aesni.o $(SRCDIR)/sm4_gfni.o $(SRCDIR)/sm4_gcm.o $(SRCDIR)/utils.o $(SRCDIR)/cpu_detect.o

# Targets
.PHONY: all clean test benchmark debug help

all: test_sm4 benchmark_sm4

# Main test executable
test_sm4: $(ALL_OBJS) $(TESTDIR)/test_sm4.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

# Benchmark executable
benchmark_sm4: $(ALL_OBJS) $(BENCHDIR)/benchmark.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

# Debug versions
debug: CFLAGS = $(CFLAGS_DEBUG)
debug: test_sm4_debug benchmark_sm4_debug

test_sm4_debug: $(ALL_OBJS) $(TESTDIR)/test_sm4.o
	$(CC) $(CFLAGS_DEBUG) -o $@ $^ $(LDFLAGS)

benchmark_sm4_debug: $(ALL_OBJS) $(BENCHDIR)/benchmark.o
	$(CC) $(CFLAGS_DEBUG) -o $@ $^ $(LDFLAGS)

# Individual implementations
basic: $(BASIC_OBJS) $(TESTDIR)/test_sm4.o
	$(CC) $(CFLAGS) -o test_basic $^ $(LDFLAGS)

ttable: $(TTABLE_OBJS) $(TESTDIR)/test_sm4.o
	$(CC) $(CFLAGS) -o test_ttable $^ $(LDFLAGS)

aesni: $(AESNI_OBJS) $(TESTDIR)/test_sm4.o
	$(CC) $(CFLAGS) -maes -mpclmul -o test_aesni $^ $(LDFLAGS)

gfni: $(GFNI_OBJS) $(TESTDIR)/test_sm4.o
	$(CC) $(CFLAGS) -mgfni -mavx2 -mavx512f -o test_gfni $^ $(LDFLAGS)

# Object file compilation rules
$(SRCDIR)/%.o: $(SRCDIR)/%.c $(SRCDIR)/sm4.h
	$(CC) $(CFLAGS) -c -o $@ $<

$(SRCDIR)/sm4_aesni.o: $(SRCDIR)/sm4_aesni.c $(SRCDIR)/sm4.h
	$(CC) $(CFLAGS) -maes -mpclmul -c -o $@ $<

$(SRCDIR)/sm4_gfni.o: $(SRCDIR)/sm4_gfni.c $(SRCDIR)/sm4.h
	$(CC) $(CFLAGS) -mgfni -mavx2 -mavx512f -c -o $@ $<

$(TESTDIR)/%.o: $(TESTDIR)/%.c
	$(CC) $(CFLAGS) -c -o $@ $<

$(BENCHDIR)/%.o: $(BENCHDIR)/%.c
	$(CC) $(CFLAGS) -c -o $@ $<

# Test targets
test: test_sm4
	@echo "Running SM4 test suite..."
	./test_sm4

test-basic: basic
	@echo "Running basic implementation test..."
	./test_basic

test-ttable: ttable
	@echo "Running T-table implementation test..."
	./test_ttable

test-aesni: aesni
	@echo "Running AES-NI implementation test..."
	./test_aesni

test-gfni: gfni
	@echo "Running GFNI implementation test..."
	./test_gfni

# Benchmark targets
benchmark: benchmark_sm4
	@echo "Running SM4 performance benchmark..."
	./benchmark_sm4

benchmark-quick: benchmark_sm4
	@echo "Running quick performance benchmark..."
	./benchmark_sm4 | head -20

# Verification targets
verify: test_sm4
	@echo "Running comprehensive verification..."
	./test_sm4
	@echo "Verification complete."

# Performance analysis
perf: benchmark_sm4
	@echo "Running performance analysis..."
	perf record -g ./benchmark_sm4
	perf report

# Memory analysis
memcheck: test_sm4
	@echo "Running memory analysis..."
	valgrind --tool=memcheck --leak-check=full ./test_sm4

# Static analysis
analyze:
	@echo "Running static analysis..."
	cppcheck --enable=all $(SRCDIR)/ $(TESTDIR)/ $(BENCHDIR)/

# Code coverage
coverage: CFLAGS += --coverage
coverage: LDFLAGS += --coverage
coverage: test_sm4
	@echo "Running code coverage analysis..."
	./test_sm4
	gcov $(SRCDIR)/*.c
	lcov --capture --directory . --output-file coverage.info
	genhtml coverage.info --output-directory coverage_html

# Assembly output
asm: $(SRCDIR)/sm4_basic.c $(SRCDIR)/sm4_ttable.c $(SRCDIR)/sm4_aesni.c
	@echo "Generating assembly output..."
	$(CC) $(CFLAGS) -S -o $(SRCDIR)/sm4_basic.s $(SRCDIR)/sm4_basic.c
	$(CC) $(CFLAGS) -S -o $(SRCDIR)/sm4_ttable.s $(SRCDIR)/sm4_ttable.c
	$(CC) $(CFLAGS) -maes -mpclmul -S -o $(SRCDIR)/sm4_aesni.s $(SRCDIR)/sm4_aesni.c

# Clean targets
clean:
	rm -f $(SRCDIR)/*.o $(TESTDIR)/*.o $(BENCHDIR)/*.o
	rm -f test_sm4 benchmark_sm4 test_sm4_debug benchmark_sm4_debug
	rm -f test_basic test_ttable test_aesni test_gfni
	rm -f $(SRCDIR)/*.s
	rm -f *.gcov *.gcda *.gcno coverage.info
	rm -rf coverage_html

clean-all: clean
	rm -f perf.data*

# Installation (optional)
install: test_sm4 benchmark_sm4
	@echo "Installing SM4 tools..."
	cp test_sm4 /usr/local/bin/sm4-test
	cp benchmark_sm4 /usr/local/bin/sm4-benchmark

uninstall:
	@echo "Uninstalling SM4 tools..."
	rm -f /usr/local/bin/sm4-test
	rm -f /usr/local/bin/sm4-benchmark

# Help target
help:
	@echo "SM4 Implementation Makefile"
	@echo ""
	@echo "Available targets:"
	@echo "  all          - Build test suite and benchmark"
	@echo "  test         - Build and run test suite"
	@echo "  benchmark    - Build and run performance benchmark"
	@echo "  debug        - Build debug versions"
	@echo "  clean        - Clean build files"
	@echo ""
	@echo "Individual implementations:"
	@echo "  basic        - Build basic implementation"
	@echo "  ttable       - Build T-table optimized implementation"
	@echo "  aesni        - Build AES-NI optimized implementation"
	@echo "  gfni         - Build GFNI optimized implementation"
	@echo ""
	@echo "Testing targets:"
	@echo "  test-basic   - Test basic implementation"
	@echo "  test-ttable  - Test T-table implementation"
	@echo "  test-aesni   - Test AES-NI implementation"
	@echo "  test-gfni    - Test GFNI implementation"
	@echo "  verify       - Run comprehensive verification"
	@echo ""
	@echo "Analysis targets:"
	@echo "  perf         - Run performance profiling"
	@echo "  memcheck     - Run memory analysis"
	@echo "  analyze      - Run static analysis"
	@echo "  coverage     - Generate code coverage report"
	@echo "  asm          - Generate assembly output"
	@echo ""
	@echo "Compiler flags:"
	@echo "  CFLAGS = $(CFLAGS)"
