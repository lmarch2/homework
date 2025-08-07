CC = gcc
CFLAGS = -Wall -Wextra -std=c99
SRCDIR = src
TESTDIR = tests
BENCHDIR = benchmark
OBJDIR = obj
BINDIR = bin

BASIC_CFLAGS = $(CFLAGS) -O0
OPTIMIZED_CFLAGS = $(CFLAGS) -O2
AGGRESSIVE_CFLAGS = $(CFLAGS) -O3 -march=native -funroll-loops

SOURCES = $(SRCDIR)/sm3_basic.c $(SRCDIR)/sm3_optimized.c $(SRCDIR)/length_extension.c $(SRCDIR)/merkle_tree.c
OBJECTS = $(SOURCES:$(SRCDIR)/%.c=$(OBJDIR)/%_basic.o)
OPT_OBJECTS = $(SOURCES:$(SRCDIR)/%.c=$(OBJDIR)/%_opt.o)
AGG_OBJECTS = $(SOURCES:$(SRCDIR)/%.c=$(OBJDIR)/%_agg.o)

TESTS = $(BINDIR)/test_sm3_basic $(BINDIR)/test_sm3_opt $(BINDIR)/test_sm3_agg \
        $(BINDIR)/test_attack_basic $(BINDIR)/test_attack_opt $(BINDIR)/test_attack_agg \
        $(BINDIR)/test_merkle_basic $(BINDIR)/test_merkle_opt $(BINDIR)/test_merkle_agg

# 新增的便捷目标
.PHONY: demo test_sm3 test_length test_merkle benchmark

BENCHMARKS = $(BINDIR)/performance_basic $(BINDIR)/performance_opt $(BINDIR)/performance_agg

.PHONY: all clean test benchmark setup

all: setup $(TESTS) $(BENCHMARKS)

setup:
	@mkdir -p $(OBJDIR) $(BINDIR)

# Basic optimization level (-O0)
$(OBJDIR)/%_basic.o: $(SRCDIR)/%.c
	$(CC) $(BASIC_CFLAGS) -c $< -o $@

# Standard optimization level (-O2)
$(OBJDIR)/%_opt.o: $(SRCDIR)/%.c
	$(CC) $(OPTIMIZED_CFLAGS) -c $< -o $@

# Aggressive optimization level (-O3 -march=native -funroll-loops)
$(OBJDIR)/%_agg.o: $(SRCDIR)/%.c
	$(CC) $(AGGRESSIVE_CFLAGS) -c $< -o $@

# Test executables
$(BINDIR)/test_sm3_basic: $(TESTDIR)/test_sm3.c $(OBJDIR)/sm3_basic_basic.o $(OBJDIR)/sm3_optimized_basic.o $(OBJDIR)/length_extension_basic.o
	$(CC) $(BASIC_CFLAGS) $^ -o $@

$(BINDIR)/test_sm3_opt: $(TESTDIR)/test_sm3.c $(OBJDIR)/sm3_basic_opt.o $(OBJDIR)/sm3_optimized_opt.o $(OBJDIR)/length_extension_opt.o
	$(CC) $(OPTIMIZED_CFLAGS) $^ -o $@

$(BINDIR)/test_sm3_agg: $(TESTDIR)/test_sm3.c $(OBJDIR)/sm3_basic_agg.o $(OBJDIR)/sm3_optimized_agg.o $(OBJDIR)/length_extension_agg.o
	$(CC) $(AGGRESSIVE_CFLAGS) $^ -o $@

$(BINDIR)/test_attack_basic: $(TESTDIR)/test_attack.c $(OBJDIR)/sm3_basic_basic.o $(OBJDIR)/sm3_optimized_basic.o $(OBJDIR)/length_extension_basic.o
	$(CC) $(BASIC_CFLAGS) $^ -o $@

$(BINDIR)/test_attack_opt: $(TESTDIR)/test_attack.c $(OBJDIR)/sm3_basic_opt.o $(OBJDIR)/sm3_optimized_opt.o $(OBJDIR)/length_extension_opt.o
	$(CC) $(OPTIMIZED_CFLAGS) $^ -o $@

$(BINDIR)/test_attack_agg: $(TESTDIR)/test_attack.c $(OBJDIR)/sm3_basic_agg.o $(OBJDIR)/sm3_optimized_agg.o $(OBJDIR)/length_extension_agg.o
	$(CC) $(AGGRESSIVE_CFLAGS) $^ -o $@

$(BINDIR)/test_merkle_basic: $(TESTDIR)/test_merkle.c $(OBJDIR)/sm3_basic_basic.o $(OBJDIR)/sm3_optimized_basic.o $(OBJDIR)/merkle_tree_basic.o
	$(CC) $(BASIC_CFLAGS) $^ -o $@ -lm

$(BINDIR)/test_merkle_opt: $(TESTDIR)/test_merkle.c $(OBJDIR)/sm3_basic_opt.o $(OBJDIR)/sm3_optimized_opt.o $(OBJDIR)/merkle_tree_opt.o
	$(CC) $(OPTIMIZED_CFLAGS) $^ -o $@ -lm

$(BINDIR)/test_merkle_agg: $(TESTDIR)/test_merkle.c $(OBJDIR)/sm3_basic_agg.o $(OBJDIR)/sm3_optimized_agg.o $(OBJDIR)/merkle_tree_agg.o
	$(CC) $(AGGRESSIVE_CFLAGS) $^ -o $@ -lm

# Benchmark executables
$(BINDIR)/performance_basic: $(BENCHDIR)/performance.c $(OBJDIR)/sm3_basic_basic.o $(OBJDIR)/sm3_optimized_basic.o $(OBJDIR)/merkle_tree_basic.o
	$(CC) $(BASIC_CFLAGS) $^ -o $@ -lm

$(BINDIR)/performance_opt: $(BENCHDIR)/performance.c $(OBJDIR)/sm3_basic_opt.o $(OBJDIR)/sm3_optimized_opt.o $(OBJDIR)/merkle_tree_opt.o
	$(CC) $(OPTIMIZED_CFLAGS) $^ -o $@ -lm

$(BINDIR)/performance_agg: $(BENCHDIR)/performance.c $(OBJDIR)/sm3_basic_agg.o $(OBJDIR)/sm3_optimized_agg.o $(OBJDIR)/merkle_tree_agg.o
	$(CC) $(AGGRESSIVE_CFLAGS) $^ -o $@ -lm

# Test targets
test: test-basic test-opt test-agg

test-basic: $(BINDIR)/test_sm3_basic $(BINDIR)/test_attack_basic $(BINDIR)/test_merkle_basic
	@echo "Running basic optimization tests..."
	@echo "==================================="
	./$(BINDIR)/test_sm3_basic
	@echo ""
	./$(BINDIR)/test_attack_basic
	@echo ""
	./$(BINDIR)/test_merkle_basic

test-opt: $(BINDIR)/test_sm3_opt $(BINDIR)/test_attack_opt $(BINDIR)/test_merkle_opt
	@echo "Running optimized tests..."
	@echo "=========================="
	./$(BINDIR)/test_sm3_opt
	@echo ""
	./$(BINDIR)/test_attack_opt
	@echo ""
	./$(BINDIR)/test_merkle_opt

test-agg: $(BINDIR)/test_sm3_agg $(BINDIR)/test_attack_agg $(BINDIR)/test_merkle_agg
	@echo "Running aggressively optimized tests..."
	@echo "======================================"
	./$(BINDIR)/test_sm3_agg
	@echo ""
	./$(BINDIR)/test_attack_agg
	@echo ""
	./$(BINDIR)/test_merkle_agg

# Benchmark targets
benchmark: benchmark-basic benchmark-opt benchmark-agg

benchmark-basic: $(BINDIR)/performance_basic
	@echo "Running basic optimization benchmark..."
	@echo "======================================"
	./$(BINDIR)/performance_basic > results_basic.txt
	@echo "Results saved to results_basic.txt"

benchmark-opt: $(BINDIR)/performance_opt
	@echo "Running optimized benchmark..."
	@echo "============================="
	./$(BINDIR)/performance_opt > results_opt.txt
	@echo "Results saved to results_opt.txt"

benchmark-agg: $(BINDIR)/performance_agg
	@echo "Running aggressively optimized benchmark..."
	@echo "=========================================="
	./$(BINDIR)/performance_agg > results_agg.txt
	@echo "Results saved to results_agg.txt"

# Quick test - runs optimized version only
quick-test: $(BINDIR)/test_sm3_opt $(BINDIR)/test_attack_opt $(BINDIR)/test_merkle_opt
	@echo "Running quick validation tests..."
	@echo "================================"
	./$(BINDIR)/test_sm3_opt
	./$(BINDIR)/test_attack_opt
	./$(BINDIR)/test_merkle_opt

# Performance comparison
compare: $(BINDIR)/performance_basic $(BINDIR)/performance_opt $(BINDIR)/performance_agg
	@echo "Running performance comparison..."
	@echo "================================"
	@echo "Basic (-O0):" > comparison.txt
	./$(BINDIR)/performance_basic >> comparison.txt
	@echo "" >> comparison.txt
	@echo "Optimized (-O2):" >> comparison.txt
	./$(BINDIR)/performance_opt >> comparison.txt
	@echo "" >> comparison.txt
	@echo "Aggressive (-O3 -march=native -funroll-loops):" >> comparison.txt
	./$(BINDIR)/performance_agg >> comparison.txt
	@echo "Performance comparison saved to comparison.txt"

clean:
	rm -rf $(OBJDIR) $(BINDIR) *.txt

help:
	@echo "Available targets:"
	@echo "  all           - Build all executables"
	@echo "  test          - Run all tests"
	@echo "  test-basic    - Run tests with basic optimization"
	@echo "  test-opt      - Run tests with standard optimization"
	@echo "  test-agg      - Run tests with aggressive optimization"
	@echo "  benchmark     - Run all benchmarks"
	@echo "  benchmark-*   - Run specific optimization level benchmark"
	@echo "  quick-test    - Run optimized tests only"
	@echo "  compare       - Compare all optimization levels"
	@echo "  demo          - Build and run main demonstration"
	@echo "  test_sm3      - Build and run SM3 tests"
	@echo "  test_length   - Build and run length extension tests"
	@echo "  test_merkle   - Build and run Merkle tree tests"

# 便捷目标
demo: $(BINDIR)/project_demo

test_sm3: $(BINDIR)/test_sm3_opt
	./$(BINDIR)/test_sm3_opt

test_length: $(BINDIR)/test_attack_opt  
	./$(BINDIR)/test_attack_opt

test_merkle: $(BINDIR)/test_merkle_opt
	./$(BINDIR)/test_merkle_opt

$(BINDIR)/project_demo: $(TESTDIR)/project_demo.c $(SRCDIR)/sm3_basic.c | $(BINDIR)
	$(CC) $(OPTIMIZED_CFLAGS) -o $@ $^ -lm
	@echo "  clean         - Remove build artifacts"
	@echo "  help          - Show this help message"
