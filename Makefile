BUILD_DIR=build

.PHONY: run_benchmark
run_benchmark: $(BUILD_DIR)/ldc_benchmark $(BUILD_DIR)/dmd_benchmark $(BUILD_DIR)/gdc_benchmark
	$(BUILD_DIR)/gdc_benchmark
	$(BUILD_DIR)/ldc_benchmark
	$(BUILD_DIR)/dmd_benchmark

$(BUILD_DIR)/gdc_benchmark: benchmark.d murmurhash3.d $(BUILD_DIR)/CMurmurHash3_g++.o
	gdc -O3 -frelease -Wall -Werror $^ -o$@

$(BUILD_DIR)/ldc_benchmark: benchmark.d murmurhash3.d $(BUILD_DIR)/CMurmurHash3_clang.o
	ldc2 -O3 -release -inline $^ -of$@

$(BUILD_DIR)/dmd_benchmark: benchmark.d murmurhash3.d $(BUILD_DIR)/CMurmurHash3_g++.o
	dmd -O -release -inline $^ -of$@

$(BUILD_DIR)/CMurmurHash3_clang.o: smasher/src/MurmurHash3.cpp | $(BUILD_DIR)
	clang++ -I/smasher/src -O3 -Wall -Werror -c $< -o $@

$(BUILD_DIR)/CMurmurHash3_g++.o: smasher/src/MurmurHash3.cpp | $(BUILD_DIR)
	g++ -I/smasher/src -O3 -Wall -Werror -c $< -o $@

.PHONY: clean
clean:
	rm -Rf $(BUILD_DIR) *.o

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)
