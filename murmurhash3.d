/**
Computes MurmurHash3 hashes of arbitrary data. MurmurHash is a non-cryptographic
hash function suitable for general hash-based lookup.

MurmurHash3 yields a 32-bit or 128-bit hash value.

This module conforms to the APIs defined in $(D std.digest.digest).
To understand the differences between the template and the OOP API, see $(D std.digest.digest).

This module publicly imports $(D std.digest.digest) and can be used as a stand-alone module.

License:   $(WEB www.boost.org/LICENSE_1_0.txt, Boost License 1.0).
Authors: Guillaume Chatelet $(BR)
References:
  $(LINK2 https://code.google.com/p/smhasher/wiki/MurmurHash3, reference implementation)
  $(LINK2 https://en.wikipedia.org/wiki/MurmurHash, Wikipedia on MurmurHash)
*/
//module std.digest.murmurhash3;

public import std.digest.digest;

@safe:

alias MurmurHash3_x86_32 = Piecewise!SMurmurHash3_x86_32;
alias MurmurHash3_x86_128 = Piecewise!SMurmurHash3_x86_128;
alias MurmurHash3_x64_128 = Piecewise!SMurmurHash3_x64_128;

alias MurmurHash3_x86_32Digest = WrapperDigest!MurmurHash3_x86_32;
alias MurmurHash3_x86_128Digest = WrapperDigest!MurmurHash3_x86_128;
alias MurmurHash3_x64_128Digest = WrapperDigest!MurmurHash3_x64_128;

/**
MurmurHash3 cannot put chunks smaller than Block.sizeof at a time. This struct
stores remainder bytes in a buffer and pushes it as soon as the block is
complete or during finalization.
*/
struct Piecewise(Hasher)
{
    enum blockSize = bits!Block;

    alias Block = Hasher.Block;
    union BufferUnion
    {
        Block block;
        ubyte[Block.sizeof] data;
    }

    BufferUnion buffer;
    size_t bufferSize;
    Hasher hasher;

    void start()
    {
        this = Piecewise.init;
    }

    void put(scope const(ubyte[]) data...) pure nothrow @trusted
    {
        // Buffer should never be full while entering this function.
        assert(bufferSize < Block.sizeof);

        const(ubyte)* start = data.ptr;

        // Check if we have some leftover data in the buffer. Then fill the first block buffer.
        if (bufferSize + data.length < Block.sizeof)
        {
            buffer.data[bufferSize .. bufferSize + data.length] = start[0 .. data.length];
            bufferSize += data.length;
            return;
        }
        const preprocessed = Block.sizeof - bufferSize;
        buffer.data[bufferSize .. $] = start[0 .. preprocessed];
        hasher.putBlock(buffer.block);
        start += preprocessed;

        // Do main work: process chunks of Block.sizeof bytes
        const numBlocks = (data.length - preprocessed) / Block.sizeof;
        const(ubyte)* end = start + numBlocks * Block.sizeof;

        for (; start < end; start += Block.sizeof)
        {
            buffer.data = start[0 .. Block.sizeof];
            hasher.putBlock(buffer.block);
        }
        // +1 for preprocessed Block
        hasher.size += (numBlocks + 1) * Block.sizeof;

        // Now add remaining data to buffer
        bufferSize = data.length - preprocessed - numBlocks * Block.sizeof;
        buffer.data[0 .. bufferSize] = end[0 .. bufferSize];
    }

    ubyte[Block.sizeof] finish() pure nothrow
    {
        auto tail = getRemainder();
        if (tail.length > 0)
        {
            hasher.putRemainder(tail);
        }
        hasher.finalize();
        return hasher.getBytes();
    }

private:
    const(ubyte)[] getRemainder()
    {
        return buffer.data[0 .. bufferSize];
    }
}

unittest
{
    struct DummyHasher
    {
        alias Block = ubyte[2];
        const(Block)[] results;
        size_t size;

        void putBlock(Block value) pure nothrow
        {
            results ~= value;
        }

        void putRemainder(scope const(ubyte)[] data...) pure nothrow
        {
        }

        void finalize() pure nothrow
        {
        }

        Block getBytes() pure nothrow
        {
            return Block.init;
        }
    }

    auto digester = Piecewise!DummyHasher();
    assert(digester.hasher.results == []);
    assert(digester.getRemainder() == []);
    digester.put(0);
    assert(digester.hasher.results == []);
    assert(digester.getRemainder() == [0]);
    digester.put(1, 2);
    assert(digester.hasher.results == [[0, 1]]);
    assert(digester.getRemainder() == [2]);
    digester.put(3, 4, 5);
    assert(digester.hasher.results == [[0, 1], [2, 3], [4, 5]]);
    assert(digester.getRemainder() == []);
}

void putBlocks(H, Block = H.Block)(ref H hash, scope const(Block[]) blocks...) pure nothrow @nogc @trusted
{
    with (hash)
    {
        const(Block)* start = blocks.ptr;
        const(Block*) end = blocks.ptr + blocks.length;
        for (; start < end; start++)
        {
            putBlock(*start);
        }
        size += blocks.length * Block.sizeof;
    }
}

auto getBytes(H)(ref H hash) pure nothrow @nogc
{
    static if (is(H.Block == uint))
    {
        return cast(ubyte[H.Block.sizeof]) cast(uint[1]) [hash.get()];
    }
    else
    {
        return cast(ubyte[H.Block.sizeof]) hash.get();
    }
}

/**
MurmurHash3 for x86 processors producing a 32 bits value.

This is a lower level implementation that makes finalization optional and have
slightly better performance.
Note that $(D putRemainder) can be called only once and that no subsequent calls
to putBlocks is allowed.
*/
struct SMurmurHash3_x86_32
{
private:
    enum uint c1 = 0xcc9e2d51;
    enum uint c2 = 0x1b873593;
    uint h1;

public:
    alias Block = uint;
    size_t size;

    this(uint seed)
    {
        h1 = seed;
    }

    @disable this(this);

    void putBlock(uint block) pure nothrow @nogc
    {
        update(h1, block, 0, c1, c2, 15, 13, 0xe6546b64);
    }

    void putRemainder(scope const(ubyte[]) data...) pure nothrow @nogc
    {
        assert(data.length < Block.sizeof);
        assert(data.length >= 0);
        size += data.length;
        uint k1 = 0;
        final switch (data.length & 3)
        {
        case 3:
            k1 ^= data[2] << 16;
            goto case;
        case 2:
            k1 ^= data[1] << 8;
            goto case;
        case 1:
            k1 ^= data[0];
            h1 ^= shuffle(k1, c1, c2, 15);
            goto case;
        case 0:
        }
    }

    void finalize() pure nothrow @nogc
    {
        h1 ^= size;
        h1 = fmix(h1);
    }

    int get() pure nothrow @nogc
    {
        return h1;
    }
}

version (unittest)
{
    @trusted string toHex(const(ubyte)[] hash)
    {
        return toHexString(hash).idup;
    }

    import std.string : representation;

    string digestToHex(T)(string data, uint seed = 0)
    {
        return digest!(T)(data).toHex();
    }
}

///
unittest
{
    const(uint)[] data = [1, 2, 3, 4];
    SMurmurHash3_x86_32 hasher;
    hasher.putBlocks(data); // call many times if you need.
    hasher.putRemainder( /* bytes */ ); // put remainder bytes if needed.
    hasher.finalize(); // always finalize before calling get.
    assert(hasher.get() == 1145416960);
}

unittest
{
    alias toHex = digestToHex!MurmurHash3_x86_32;
    assert(toHex("") == "00000000");
    assert(toHex("a") == "B269253C");
    assert(toHex("ab") == "5FD7BF9B");
    assert(toHex("abc") == "FA93DDB3");
    assert(toHex("abcd") == "6A67ED43");
    assert(toHex("abcde") == "F69A9BE8");
    assert(toHex("abcdef") == "85C08161");
    assert(toHex("abcdefg") == "069B3C88");
    assert(toHex("abcdefgh") == "C4CCDD49");
    assert(toHex("abcdefghi") == "F0061442");
    assert(toHex("abcdefghij") == "91779288");
    assert(toHex("abcdefghijk") == "DF253B5F");
    assert(toHex("abcdefghijkl") == "273D6FA3");
    assert(toHex("abcdefghijklm") == "1B1612F2");
    assert(toHex("abcdefghijklmn") == "F06D52F8");
    assert(toHex("abcdefghijklmno") == "D2F7099D");
    assert(toHex("abcdefghijklmnop") == "ED9162E7");
    assert(toHex("abcdefghijklmnopq") == "4A5E65B6");
    assert(toHex("abcdefghijklmnopqr") == "94A819C2");
    assert(toHex("abcdefghijklmnopqrs") == "C15BBF85");
    assert(toHex("abcdefghijklmnopqrst") == "9A711CBE");
    assert(toHex("abcdefghijklmnopqrstu") == "ABE7195A");
    assert(toHex("abcdefghijklmnopqrstuv") == "C73CB670");
    assert(toHex("abcdefghijklmnopqrstuvw") == "1C4D1EA5");
    assert(toHex("abcdefghijklmnopqrstuvwx") == "3939F9B0");
    assert(toHex("abcdefghijklmnopqrstuvwxy") == "1A568338");
    assert(toHex("abcdefghijklmnopqrstuvwxyz") == "6D034EA3");

    // Pushing pieces shorter than block size.
    auto hasher = MurmurHash3_x86_32();
    hasher.put(['a', 'b']);
    hasher.put(['c', 'd']);
    assert(hasher.finish().toHex() == "6A67ED43");
}

/**
MurmurHash3 for x86 processors producing a 128 bits value.

This is a lower level implementation that makes finalization optional and have
slightly better performance.
Note that $(D putRemainder) can be called only once and that no subsequent calls
to putBlocks is allowed.
*/
struct SMurmurHash3_x86_128
{
private:
    enum uint c1 = 0x239b961b;
    enum uint c2 = 0xab0e9789;
    enum uint c3 = 0x38b34ae5;
    enum uint c4 = 0xa1e38b93;
    uint h4, h3, h2, h1;

public:
    alias Block = uint[4];
    size_t size;

    this(uint seed4, uint seed3, uint seed2, uint seed1)
    {
        h4 = seed4;
        h3 = seed3;
        h2 = seed2;
        h1 = seed1;
    }

    this(uint seed)
    {
        h4 = h3 = h2 = h1 = seed;
    }

    @disable this(this);

    void putBlock(Block block) pure nothrow @nogc
    {
        update(h1, block[0], h2, c1, c2, 15, 19, 0x561ccd1b);
        update(h2, block[1], h3, c2, c3, 16, 17, 0x0bcaa747);
        update(h3, block[2], h4, c3, c4, 17, 15, 0x96cd1c35);
        update(h4, block[3], h1, c4, c1, 18, 13, 0x32ac3b17);
    }

    void putRemainder(scope const(ubyte[]) data...) pure nothrow @nogc
    {
        assert(data.length < Block.sizeof);
        assert(data.length >= 0);
        size += data.length;
        uint k1 = 0;
        uint k2 = 0;
        uint k3 = 0;
        uint k4 = 0;

        final switch (data.length & 15)
        {
        case 15:
            k4 ^= data[14] << 16;
            goto case;
        case 14:
            k4 ^= data[13] << 8;
            goto case;
        case 13:
            k4 ^= data[12] << 0;
            h4 ^= shuffle(k4, c4, c1, 18);
            goto case;
        case 12:
            k3 ^= data[11] << 24;
            goto case;
        case 11:
            k3 ^= data[10] << 16;
            goto case;
        case 10:
            k3 ^= data[9] << 8;
            goto case;
        case 9:
            k3 ^= data[8] << 0;
            h3 ^= shuffle(k3, c3, c4, 17);
            goto case;
        case 8:
            k2 ^= data[7] << 24;
            goto case;
        case 7:
            k2 ^= data[6] << 16;
            goto case;
        case 6:
            k2 ^= data[5] << 8;
            goto case;
        case 5:
            k2 ^= data[4] << 0;
            h2 ^= shuffle(k2, c2, c3, 16);
            goto case;
        case 4:
            k1 ^= data[3] << 24;
            goto case;
        case 3:
            k1 ^= data[2] << 16;
            goto case;
        case 2:
            k1 ^= data[1] << 8;
            goto case;
        case 1:
            k1 ^= data[0] << 0;
            h1 ^= shuffle(k1, c1, c2, 15);
            goto case;
        case 0:
        }
    }

    void finalize() pure nothrow @nogc
    {
        h1 ^= size;
        h2 ^= size;
        h3 ^= size;
        h4 ^= size;

        h1 += h2;
        h1 += h3;
        h1 += h4;
        h2 += h1;
        h3 += h1;
        h4 += h1;

        h1 = fmix(h1);
        h2 = fmix(h2);
        h3 = fmix(h3);
        h4 = fmix(h4);

        h1 += h2;
        h1 += h3;
        h1 += h4;
        h2 += h1;
        h3 += h1;
        h4 += h1;
    }

    Block get() pure nothrow @nogc
    {
        return [h1, h2, h3, h4];
    }
}

unittest
{
    alias toHex = digestToHex!MurmurHash3_x86_128;
    assert(toHex("") == "00000000000000000000000000000000");
    assert(toHex("a") == "3C9394A71BB056551BB056551BB05655");
    assert(toHex("ab") == "DF5184151030BE251030BE251030BE25");
    assert(toHex("abc") == "D1C6CD75A506B0A2A506B0A2A506B0A2");
    assert(toHex("abcd") == "AACCB6962EC6AF452EC6AF452EC6AF45");
    assert(toHex("abcde") == "FB2E40C5BCC5245D7701725A7701725A");
    assert(toHex("abcdef") == "0AB97CE12127AFA1F9DFBEA9F9DFBEA9");
    assert(toHex("abcdefg") == "D941B590DE3A86092869774A2869774A");
    assert(toHex("abcdefgh") == "3611F4AE8714B1AD92806CFA92806CFA");
    assert(toHex("abcdefghi") == "1C8C05AD6F590622107DD2147C4194DD");
    assert(toHex("abcdefghij") == "A72ED9F50E90379A2AAA92C77FF12F69");
    assert(toHex("abcdefghijk") == "DDC9C8A01E111FCA2DF1FE8257975EBD");
    assert(toHex("abcdefghijkl") == "FE038573C02482F4ADDFD42753E58CD2");
    assert(toHex("abcdefghijklm") == "15A23AC1ECA1AEDB66351CF470DE2CD9");
    assert(toHex("abcdefghijklmn") == "8E11EC75D71F5D60F4456F944D89D4F1");
    assert(toHex("abcdefghijklmno") == "691D6DEEAED51A4A5714CE84A861A7AD");
    assert(toHex("abcdefghijklmnop") == "2776D29F5612B990218BCEE445BA93D1");
    assert(toHex("abcdefghijklmnopq") == "D3A445046F5C51642ADC6DD99D07111D");
    assert(toHex("abcdefghijklmnopqr") == "AA5493A0DA291D966A9E7128585841D9");
    assert(toHex("abcdefghijklmnopqrs") == "281B6A4F9C45B9BFC3B77850930F2C20");
    assert(toHex("abcdefghijklmnopqrst") == "19342546A8216DB62873B49E545DCB1F");
    assert(toHex("abcdefghijklmnopqrstu") == "A6C0F30D6C738620E7B9590D2E088D99");
    assert(toHex("abcdefghijklmnopqrstuv") == "A7D421D9095CDCEA393CBBA908342384");
    assert(toHex("abcdefghijklmnopqrstuvw") == "C3A93D572B014949317BAD7EE809158F");
    assert(toHex("abcdefghijklmnopqrstuvwx") == "802381D77956833791F87149326E4801");
    assert(toHex("abcdefghijklmnopqrstuvwxy") == "0AC619A5302315755A80D74ADEFAA842");
    assert(toHex("abcdefghijklmnopqrstuvwxyz") == "1306343E662F6F666E56F6172C3DE344");

    // Pushing pieces shorter than block size.
    auto hasher = MurmurHash3_x86_128();
    hasher.put(['a', 'b']);
    hasher.put(['c', 'd']);
    assert(hasher.finish().toHex() == "AACCB6962EC6AF452EC6AF452EC6AF45");
}

/**
MurmurHash3 for x86_64 processors producing a 128 bits value.

This is a lower level implementation that makes finalization optional and have
slightly better performance.
Note that $(D putRemainder) can be called only once and that no subsequent calls
to putBlocks is allowed.
*/
struct SMurmurHash3_x64_128
{
private:
    enum ulong c1 = 0x87c37b91114253d5;
    enum ulong c2 = 0x4cf5ad432745937f;
    ulong h2, h1;

public:
    alias Block = ulong[2];
    size_t size;

    this(ulong seed)
    {
        h2 = h1 = seed;
    }

    this(ulong seed2, ulong seed1)
    {
        h2 = seed2;
        h1 = seed1;
    }

    @disable this(this);

    void putBlock(Block block) pure nothrow @nogc
    {
        update(h1, block[0], h2, c1, c2, 31, 27, 0x52dce729);
        update(h2, block[1], h1, c2, c1, 33, 31, 0x38495ab5);
    }

    void putRemainder(scope const(ubyte[]) data...) pure nothrow @nogc
    {
        assert(data.length < Block.sizeof);
        assert(data.length >= 0);
        size += data.length;
        ulong k1 = 0;
        ulong k2 = 0;
        final switch (data.length & 15)
        {
        case 15:
            k2 ^= ulong(data[14]) << 48;
            goto case;
        case 14:
            k2 ^= ulong(data[13]) << 40;
            goto case;
        case 13:
            k2 ^= ulong(data[12]) << 32;
            goto case;
        case 12:
            k2 ^= ulong(data[11]) << 24;
            goto case;
        case 11:
            k2 ^= ulong(data[10]) << 16;
            goto case;
        case 10:
            k2 ^= ulong(data[9]) << 8;
            goto case;
        case 9:
            k2 ^= ulong(data[8]) << 0;
            h2 ^= shuffle(k2, c2, c1, 33);
            goto case;
        case 8:
            k1 ^= ulong(data[7]) << 56;
            goto case;
        case 7:
            k1 ^= ulong(data[6]) << 48;
            goto case;
        case 6:
            k1 ^= ulong(data[5]) << 40;
            goto case;
        case 5:
            k1 ^= ulong(data[4]) << 32;
            goto case;
        case 4:
            k1 ^= ulong(data[3]) << 24;
            goto case;
        case 3:
            k1 ^= ulong(data[2]) << 16;
            goto case;
        case 2:
            k1 ^= ulong(data[1]) << 8;
            goto case;
        case 1:
            k1 ^= ulong(data[0]) << 0;
            h1 ^= shuffle(k1, c1, c2, 31);
            goto case;
        case 0:
        }
    }

    void finalize() pure nothrow @nogc
    {
        h1 ^= size;
        h2 ^= size;

        h1 += h2;
        h2 += h1;
        h1 = fmix(h1);
        h2 = fmix(h2);
        h1 += h2;
        h2 += h1;
    }

    Block get() pure nothrow @nogc
    {
        return [h1, h2];
    }
}

unittest
{
    alias toHex = digestToHex!MurmurHash3_x64_128;
    assert(toHex("") == "00000000000000000000000000000000");
    assert(toHex("a") == "897859F6655555855A890E51483AB5E6");
    assert(toHex("ab") == "2E1BED16EA118B93ADD4529B01A75EE6");
    assert(toHex("abc") == "6778AD3F3F3F96B4522DCA264174A23B");
    assert(toHex("abcd") == "4FCD5646D6B77BB875E87360883E00F2");
    assert(toHex("abcde") == "B8BB96F491D036208CECCF4BA0EEC7C5");
    assert(toHex("abcdef") == "55BFA3ACBF867DE45C842133990971B0");
    assert(toHex("abcdefg") == "99E49EC09F2FCDA6B6BB55B13AA23A1C");
    assert(toHex("abcdefgh") == "028CEF37B00A8ACCA14069EB600D8948");
    assert(toHex("abcdefghi") == "64793CF1CFC0470533E041B7F53DB579");
    assert(toHex("abcdefghij") == "998C2F770D5BC1B6C91A658CDC854DA2");
    assert(toHex("abcdefghijk") == "029D78DFB8D095A871E75A45E2317CBB");
    assert(toHex("abcdefghijkl") == "94E17AE6B19BF38E1C62FF7232309E1F");
    assert(toHex("abcdefghijklm") == "73FAC0A78D2848167FCCE70DFF7B652E");
    assert(toHex("abcdefghijklmn") == "E075C3F5A794D09124336AD2276009EE");
    assert(toHex("abcdefghijklmno") == "FB2F0C895124BE8A612A969C2D8C546A");
    assert(toHex("abcdefghijklmnop") == "23B74C22A33CCAC41AEB31B395D63343");
    assert(toHex("abcdefghijklmnopq") == "57A6BD887F746475E40D11A19D49DAEC");
    assert(toHex("abcdefghijklmnopqr") == "508A7F90EC8CF0776BC7005A29A8D471");
    assert(toHex("abcdefghijklmnopqrs") == "886D9EDE23BC901574946FB62A4D8AA6");
    assert(toHex("abcdefghijklmnopqrst") == "F1E237F926370B314BD016572AF40996");
    assert(toHex("abcdefghijklmnopqrstu") == "3CC9FF79E268D5C9FB3C9BE9C148CCD7");
    assert(toHex("abcdefghijklmnopqrstuv") == "56F8ABF430E388956DA9F4A8741FDB46");
    assert(toHex("abcdefghijklmnopqrstuvw") == "8E234F9DBA0A4840FFE9541CEBB7BE83");
    assert(toHex("abcdefghijklmnopqrstuvwx") == "F72CDED40F96946408F22153A3CF0F79");
    assert(toHex("abcdefghijklmnopqrstuvwxy") == "0F96072FA4CBE771DBBD9E398115EEED");
    assert(toHex("abcdefghijklmnopqrstuvwxyz") == "A94A6F517E9D9C7429D5A7B6899CADE9");

    // Pushing pieces shorter than block size.
    auto hasher = MurmurHash3_x64_128();
    hasher.put(['a', 'b']);
    hasher.put(['c', 'd']);
    assert(hasher.finish().toHex() == "4FCD5646D6B77BB875E87360883E00F2");
}

unittest
{
    // Pushing unaligned data and making sure the result is still coherent.
    void testUnalignedHash(H)()
    {
        immutable ubyte[1025] data = 0xAC;
        immutable alignedHash = digest!H(data[0 .. $ - 1]); // 0..1023
        immutable unalignedHash = digest!H(data[1 .. $]); // 1..1024
        assert(alignedHash == unalignedHash);
    }

    testUnalignedHash!MurmurHash3_x86_32();
    testUnalignedHash!MurmurHash3_x86_128();
    testUnalignedHash!MurmurHash3_x64_128();
}

private:
template bits(T)
{
    enum bits = T.sizeof * 8;
}

T rotl(T)(T x, uint y)
in
{
    import std.traits : isUnsigned;

    static assert(isUnsigned!T);
    assert(y >= 0 && y <= bits!T);
}
body
{
    return ((x << y) | (x >> (bits!T - y)));
}

T shuffle(T)(T k, T c1, T c2, ubyte r1)
{
    import std.traits : isUnsigned;

    static assert(isUnsigned!T);
    k *= c1;
    k = rotl(k, r1);
    k *= c2;
    return k;
}

void update(T)(ref T h, T k, T mixWith, T c1, T c2, ubyte r1, ubyte r2, T n)
{
    import std.traits : isUnsigned;

    static assert(isUnsigned!T);
    h ^= shuffle(k, c1, c2, r1);
    h = rotl(h, r2);
    h += mixWith;
    h = h * 5 + n;
}

uint fmix(uint h) pure nothrow @nogc
{
    h ^= h >> 16;
    h *= 0x85ebca6b;
    h ^= h >> 13;
    h *= 0xc2b2ae35;
    h ^= h >> 16;
    return h;
}

ulong fmix(ulong k) pure nothrow @nogc
{
    k ^= k >> 33;
    k *= 0xff51afd7ed558ccd;
    k ^= k >> 33;
    k *= 0xc4ceb9fe1a85ec53;
    k ^= k >> 33;
    return k;
}
