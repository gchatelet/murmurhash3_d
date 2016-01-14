extern(C++) {
	void MurmurHash3_x86_32  ( const(void*) key, int len, uint seed, void * out_ );
	void MurmurHash3_x86_128 ( const(void*) key, int len, uint seed, void * out_ );
	void MurmurHash3_x64_128 ( const(void*) key, int len, uint seed, void * out_ );
}

void main() {
	import std.stdio;
	immutable _Ki = 1024UL;
	immutable _SIZE = 256UL * _Ki; // 256 KiB
	ubyte[] buffer = new ubyte[_SIZE];
	buffer[] = 0xAC;
	auto HashC(alias H)() {
		ubyte[16] output;
		H(buffer.ptr, cast(int)(buffer.length), 0U, &output);
		return output;
	}
        import murmurhash3;
	auto useHasher(H)() {
		H hasher;
		hasher.putBlocks(cast(const(H.Block)[])buffer);
		hasher.finalize();
		return hasher.getBytes();
        }
        auto useDigestAPI(H)() {
		return digest!(Piecewise!H)(buffer);
        }
	import std.datetime : benchmark;
        immutable times = (_Ki^^3) / _SIZE;
        writeln("Please wait while benchmarking MurmurHash3, running ", times, "*hash(256KiB) = 1GiB");
        immutable descriptions = [
		"C++ MurmurHash3_x64_128", "D SMurmurHash3_x64_128", "D digest MurmurHash3_x64_128",
		"C++ MurmurHash3_x86_128", "D SMurmurHash3_x86_128", "D digest MurmurHash3_x86_128",
		"C++ MurmurHash3_x86_32",  "D SMurmurHash3_x86_32",  "D digest MurmurHash3_x86_32",
	];
        foreach (i, result; benchmark!(
		HashC!(.MurmurHash3_x64_128),useHasher!SMurmurHash3_x64_128,useDigestAPI!SMurmurHash3_x64_128,
		HashC!(.MurmurHash3_x86_128),useHasher!SMurmurHash3_x86_128,useDigestAPI!SMurmurHash3_x86_128,
		HashC!(.MurmurHash3_x86_32),useHasher!SMurmurHash3_x86_32,useDigestAPI!SMurmurHash3_x86_32,
		)(times))
        {
            writefln("%-30s - %.0f GiB/s", descriptions[i], times * 1000. / result.msecs);
        }
}
