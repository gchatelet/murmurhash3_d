import std.stdio;

import std.digest.murmurhash;

extern (C++)
{
    void MurmurHash3_x86_32(const(void*) key, int len, uint seed, void* out_);
    void MurmurHash3_x86_128(const(void*) key, int len, uint seed, void* out_);
    void MurmurHash3_x64_128(const(void*) key, int len, uint seed, void* out_);
}

void consume(void[] buf)
{
    version (GNU)
    {
        ubyte[16] tmp;
        .MurmurHash3_x86_32(buf.ptr, 0, 0, &tmp);
    }
    else
    {
        import core.bitop : volatileLoad;

        volatileLoad(cast(ubyte*) buf.ptr);
    }
}

immutable _Ki = 1024UL;
immutable _HASH_SIZE = 256UL * _Ki; // 256 KiB
immutable _TOTAL_HASH_SIZE = _Ki ^^ 3; // 1GiB
immutable _EXECUTION_COUNT = _TOTAL_HASH_SIZE / _HASH_SIZE; // 4096
ubyte[] buffer;

void BaseLineHash(alias H)()
{
    ubyte[16] tmp;
    H(buffer.ptr, cast(int)(buffer.length), 0U, &tmp);
    consume(tmp);
}

void DHash(H)()
{
    H hasher;
    hasher.putBlocks(cast(const(H.Block)[]) buffer);
    hasher.finalize();
    consume(hasher.getBytes());
}

void DDigest(H)()
{
    consume(digest!(Piecewise!H)(buffer));
}

void doBenchmark(string suffix)()
{
    import std.datetime : benchmark;

    const descriptions = ["C++", "D", "D digest"];
    auto results = benchmark!(
        mixin("BaseLineHash!(.MurmurHash3_" ~ suffix ~ ")"),
        mixin("DHash!FastMurmurHash3_" ~ suffix),
        mixin("DDigest!FastMurmurHash3_" ~ suffix))(_EXECUTION_COUNT);
    const baseline = results[0];
    foreach (i, result; results)
    {
        writefln("%-20s - %3d%% - %.2f GiB/s", suffix ~ " " ~ descriptions[i],
            100 * baseline.msecs / result.msecs, _EXECUTION_COUNT * 1000. / result.usecs);
    }
    writeln();
}

void main()
{
    buffer = new ubyte[_HASH_SIZE];
    buffer[] = 0xAC;
    writeln("Please wait while benchmarking MurmurHash3, running ",
        _EXECUTION_COUNT, "*hash(256KiB) = 1GiB");
    doBenchmark!"x64_128"();
    doBenchmark!"x86_128"();
    doBenchmark!"x86_32"();
}
