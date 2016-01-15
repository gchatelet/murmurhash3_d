extern(C++)
{
	void MurmurHash3_x86_32  ( const(void*) key, int len, uint seed, void * out_ );
	void MurmurHash3_x86_128 ( const(void*) key, int len, uint seed, void * out_ );
	void MurmurHash3_x64_128 ( const(void*) key, int len, uint seed, void * out_ );
}

void consume(void[] buf)
{
version(GNU){
	ubyte[16] tmp;
	.MurmurHash3_x86_32(buf.ptr, 0, 0, &tmp);
} else {
	import core.bitop : volatileLoad;
	volatileLoad(cast(ubyte*)buf.ptr);
}
}

void main()
{
	import std.stdio;
	immutable _Ki = 1024UL;
	immutable _SIZE = 256UL * _Ki; // 256 KiB
	ubyte[] buffer = new ubyte[_SIZE];
	buffer[] = 0xAC;
	void HashC(alias H)() {
		ubyte[16] tmp;
		H(buffer.ptr, cast(int)(buffer.length), 0U, &tmp);
		consume(tmp);
	}
        import murmurhash3;
	void useHasher(H)() {
		H hasher;
		hasher.putBlocks(cast(const(H.Block)[])buffer);
		hasher.finalize();
		consume(hasher.getBytes());
        }
        void useDigestAPI(H)() {
		consume(digest!(Piecewise!H)(buffer));
        }
	import std.datetime : benchmark;
        immutable times = (_Ki^^3) / _SIZE;
        writeln("Please wait while benchmarking MurmurHash3, running ", times, "*hash(256KiB) = 1GiB");
        auto descriptions = [
		"C++ MurmurHash3_x64_128", "D SMurmurHash3_x64_128", "D digest MurmurHash3_x64_128",
		"C++ MurmurHash3_x86_128", "D SMurmurHash3_x86_128", "D digest MurmurHash3_x86_128",
		"C++ MurmurHash3_x86_32",  "D SMurmurHash3_x86_32",  "D digest MurmurHash3_x86_32",
	];
	auto results = benchmark!(
		HashC!(.MurmurHash3_x64_128),useHasher!SMurmurHash3_x64_128,useDigestAPI!SMurmurHash3_x64_128,
		HashC!(.MurmurHash3_x86_128),useHasher!SMurmurHash3_x86_128,useDigestAPI!SMurmurHash3_x86_128,
		HashC!(.MurmurHash3_x86_32),useHasher!SMurmurHash3_x86_32,useDigestAPI!SMurmurHash3_x86_32,
		)(times);
	import std.algorithm;
	const fastest = results.reduce!min;
	import std.range : lockstep;
        foreach ( i, result; results)
        {
            writefln("%-30s - %3d%% - %.0f GiB/s", descriptions[i], 100 * fastest.msecs / result.msecs, times * 1000. / result.msecs);
        }
}
