CFLAGS=-I/smasher/src -O3 -Wall -Werror
BUILD_DIR=build

.PHONY: run_benchmark
run_benchmark: $(BUILD_DIR)/benchmark
	./$<

$(BUILD_DIR)/benchmark: benchmark.d murmurhash3.d $(BUILD_DIR)/CMurmurHash3.o
#	~/Downloads/gdc_x86_64-pc-linux-gnu/bin/gdc -O3 -frelease -Wall -Werror $^ -o$@
#	~/Downloads/ldc2-0.16.1-linux-x86_64/bin/ldc2 -O -release -inline $^ -of$@
	dmd -O -inline -release $^ -of$@

$(BUILD_DIR)/CMurmurHash3.o: smasher/src/MurmurHash3.cpp | $(BUILD_DIR)
	$(CXX) $(CFLAGS) -c $< -o $@

.PHONY: clean
clean:
	rm -Rf $(BUILD_DIR)

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)