CFLAGS=-I/smasher/src -O3 -Wall -Werror
BUILD_DIR=build

.PHONY: run_benchmark
run_benchmark: $(BUILD_DIR)/gdc_benchmark $(BUILD_DIR)/ldc_benchmark $(BUILD_DIR)/dmd_benchmark
	$(BUILD_DIR)/gdc_benchmark
	$(BUILD_DIR)/ldc_benchmark
	$(BUILD_DIR)/dmd_benchmark

$(BUILD_DIR)/gdc_benchmark: benchmark.d murmurhash3.d $(BUILD_DIR)/CMurmurHash3.o
	~/Downloads/gdc_x86_64-pc-linux-gnu/bin/gdc -O3 -frelease -fno-bounds-check -Wall -Werror $^ -o$@

$(BUILD_DIR)/ldc_benchmark: benchmark.d murmurhash3.d $(BUILD_DIR)/CMurmurHash3.o
	~/Downloads/ldc2-0.16.1-linux-x86_64/bin/ldc2 -O5 -release -inline $^ -of$@

$(BUILD_DIR)/dmd_benchmark: benchmark.d murmurhash3.d $(BUILD_DIR)/CMurmurHash3.o
	dmd -O -inline -release $^ -of$@

$(BUILD_DIR)/CMurmurHash3.o: smasher/src/MurmurHash3.cpp | $(BUILD_DIR)
	$(CXX) $(CFLAGS) -c $< -o $@

.PHONY: clean
clean:
	rm -Rf $(BUILD_DIR) *.o

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)