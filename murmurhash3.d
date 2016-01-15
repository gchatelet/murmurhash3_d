/**
Computes MurmurHash3 hashes of arbitrary data. MurmurHash is a non-cryptographic
hash function suitable for general hash-based lookup.

MurmurHash3 yields a 32-bit or 128-bit hash value.

This module conforms to the APIs defined in $(D std.digest.digest).
To understand the differences between the template and the OOP API, see $(D std.digest.digest).

This module publicly imports $(D std.digest.digest) and can be used as a stand-alone module.

License:   $(WEB www.boost.org/LICENSE_1_0.txt, Boost License 1.0).
CTFE: Digests do not work in CTFE
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
MurmurHash3 cannot put chunks smaller than blockSizeInBytes at a time. This
struct stores remainder bytes in a buffer and pushes it as soon as the  block is
complete or during finalization.
*/
struct Piecewise(Hasher)
{
    alias Block = Hasher.Block;
    enum blockSizeInBytes = Block.sizeof;
    enum blockSize = bits!Block;

    Hasher hasher;
    ubyte[blockSizeInBytes] buffer;
    size_t bufferSize = 0;

    void start()
    {
        this = Piecewise.init;
    }

    void put(scope const(ubyte)[] data...) pure nothrow
    {
        // Buffer should never be full while entring this function.
        assert(bufferSize < blockSizeInBytes);
        // Complete left over from last call if any.
        if (bufferSize > 0)
        {
            immutable available = blockSizeInBytes - bufferSize;
            immutable copySize = available < data.length ? available : data.length;
            buffer[bufferSize .. bufferSize + copySize] = data[0 .. copySize];
            data = data[copySize .. $];
            bufferSize += copySize;
        }
        // Push left over if it reached the size of a block.
        if (bufferSize == blockSizeInBytes)
        {
            hasher.putBlocks(cast(Block[1]) buffer);
            bufferSize = 0;
        }
        // Pushing as many consecutive blocks as possible.
        immutable consecutiveBlocks = alignDownTo(data.length);
        static if(true) {
          hasher.putBlocks(cast(const(Block)[]) data[0 .. consecutiveBlocks]);
        } else {
          for(size_t i = 0; i<consecutiveBlocks/Block.sizeof;i++){
            immutable Block block = (cast(const(Block)[])data)[i];
            hasher.putBlocks(block);
          }
        }
        // Adding remainder to temporary buffer.
        data = data[consecutiveBlocks .. $];
        assert(data.length < blockSizeInBytes);
        if (data.length > 0)
        {
            assert(bufferSize == 0);
            buffer[0 .. data.length] = data[];
            bufferSize += data.length;
        }
    }

    ubyte[blockSizeInBytes] finish() pure nothrow
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
        return buffer[0 .. bufferSize];
    }

    static size_t alignDownTo(size_t size)
    {
        static assert(isPowerOf2(blockSizeInBytes));
        return size & ~(blockSizeInBytes - 1UL);
    }

    static bool isPowerOf2(uint x) @nogc
    {
        return (x & -x) > (x - 1);
    }

}

unittest
{
    struct DummyHasher
    {
        alias Block = ubyte[2];
        const(Block)[] results;

        void putBlocks(const(Block)[] value) pure nothrow
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
    enum blockSizeInBytes = Block.sizeof;
    enum uint c1 = 0xcc9e2d51;
    enum uint c2 = 0x1b873593;
    uint h1;
    size_t size;

public:
    alias Block = uint;

    this(uint seed)
    {
        h1 = seed;
    }

    @disable this(this);

    void putBlocks(scope const(Block)[] blocks...) pure nothrow @nogc
    {
        foreach (block; blocks)
        {
            update(h1, block, 0, c1, c2, 15, 13, 0xe6546b64);
        }
        size += blocks.length * Block.sizeof;
    }

    void putRemainder(scope const(ubyte)[] data...) pure nothrow @nogc
    {
        assert(data.length < blockSizeInBytes);
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

    ubyte[4] getBytes() pure nothrow @nogc
    {
        return cast(ubyte[4])cast(uint[1])[h1];
    }
}

version (unittest)
{
    @trusted string toHex(const(ubyte)[] hash)
    {
        return toHexString!(Order.decreasing)(hash).idup;
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
  hasher.putRemainder(/* bytes */); // put remainder bytes if needed.
  hasher.finalize(); // always finalize before calling get.
  assert(hasher.get() == 1145416960);
}

unittest
{
    alias toHex = digestToHex!MurmurHash3_x86_32;
    assert(toHex("") == "00000000");
    assert(toHex("a") == "3C2569B2");
    assert(toHex("ab") == "9BBFD75F");
    assert(toHex("abc") == "B3DD93FA");
    assert(toHex("abcd") == "43ED676A");
    assert(toHex("abcde") == "E89B9AF6");
    assert(toHex("abcdef") == "6181C085");
    assert(toHex("abcdefg") == "883C9B06");
    assert(toHex("abcdefgh") == "49DDCCC4");
    assert(toHex("abcdefghi") == "421406F0");
    assert(toHex("abcdefghij") == "88927791");
    assert(toHex("abcdefghijk") == "5F3B25DF");
    assert(toHex("abcdefghijkl") == "A36F3D27");
    assert(toHex("abcdefghijklm") == "F212161B");
    assert(toHex("abcdefghijklmn") == "F8526DF0");
    assert(toHex("abcdefghijklmno") == "9D09F7D2");
    assert(toHex("abcdefghijklmnop") == "E76291ED");
    assert(toHex("abcdefghijklmnopq") == "B6655E4A");
    assert(toHex("abcdefghijklmnopqr") == "C219A894");
    assert(toHex("abcdefghijklmnopqrs") == "85BF5BC1");
    assert(toHex("abcdefghijklmnopqrst") == "BE1C719A");
    assert(toHex("abcdefghijklmnopqrstu") == "5A19E7AB");
    assert(toHex("abcdefghijklmnopqrstuv") == "70B63CC7");
    assert(toHex("abcdefghijklmnopqrstuvw") == "A51E4D1C");
    assert(toHex("abcdefghijklmnopqrstuvwx") == "B0F93939");
    assert(toHex("abcdefghijklmnopqrstuvwxy") == "3883561A");
    assert(toHex("abcdefghijklmnopqrstuvwxyz") == "A34E036D");

    // Pushing pieces shorter than block size.
    auto hasher = MurmurHash3_x86_32();
    hasher.put(['a', 'b']);
    hasher.put(['c', 'd']);
    assert(hasher.finish().toHex() == "43ED676A");
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
    enum blockSizeInBytes = Block.sizeof;
    enum uint c1 = 0x239b961b;
    enum uint c2 = 0xab0e9789;
    enum uint c3 = 0x38b34ae5;
    enum uint c4 = 0xa1e38b93;
    uint h4, h3, h2, h1;
    size_t size;

public:
    alias Block = uint[4];

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

    void putBlocks(scope const(Block)[] blocks...) pure nothrow @nogc
    {
        foreach (block; blocks)
        {
            update(h1, block[0], h2, c1, c2, 15, 19, 0x561ccd1b);
            update(h2, block[1], h3, c2, c3, 16, 17, 0x0bcaa747);
            update(h3, block[2], h4, c3, c4, 17, 15, 0x96cd1c35);
            update(h4, block[3], h1, c4, c1, 18, 13, 0x32ac3b17);
        }
        size += blocks.length * Block.sizeof;
    }

    void putRemainder(scope const(ubyte)[] data...) pure nothrow @nogc
    {
        assert(data.length < blockSizeInBytes);
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
        return [h4, h3, h2, h1];
    }

    ubyte[16] getBytes() pure nothrow @nogc
    {
        return cast(ubyte[16])get();
    }
}

unittest
{
    alias toHex = digestToHex!MurmurHash3_x86_128;
    assert(toHex("") == "00000000000000000000000000000000");
    assert(toHex("a") == "A794933C5556B01B5556B01B5556B01B");
    assert(toHex("ab") == "158451DF25BE301025BE301025BE3010");
    assert(toHex("abc") == "75CDC6D1A2B006A5A2B006A5A2B006A5");
    assert(toHex("abcd") == "96B6CCAA45AFC62E45AFC62E45AFC62E");
    assert(toHex("abcde") == "C5402EFB5D24C5BC5A7201775A720177");
    assert(toHex("abcdef") == "E17CB90AA1AF2721A9BEDFF9A9BEDFF9");
    assert(toHex("abcdefg") == "90B541D909863ADE4A7769284A776928");
    assert(toHex("abcdefgh") == "AEF41136ADB11487FA6C8092FA6C8092");
    assert(toHex("abcdefghi") == "AD058C1C2206596F14D27D10DD94417C");
    assert(toHex("abcdefghij") == "F5D92EA79A37900EC792AA2A692FF17F");
    assert(toHex("abcdefghijk") == "A0C8C9DDCA1F111E82FEF12DBD5E9757");
    assert(toHex("abcdefghijkl") == "738503FEF48224C027D4DFADD28CE553");
    assert(toHex("abcdefghijklm") == "C13AA215DBAEA1ECF41C3566D92CDE70");
    assert(toHex("abcdefghijklmn") == "75EC118E605D1FD7946F45F4F1D4894D");
    assert(toHex("abcdefghijklmno") == "EE6D1D694A1AD5AE84CE1457ADA761A8");
    assert(toHex("abcdefghijklmnop") == "9FD2762790B91256E4CE8B21D193BA45");
    assert(toHex("abcdefghijklmnopq") == "0445A4D364515C6FD96DDC2A1D11079D");
    assert(toHex("abcdefghijklmnopqr") == "A09354AA961D29DA28719E6AD9415858");
    assert(toHex("abcdefghijklmnopqrs") == "4F6A1B28BFB9459C5078B7C3202C0F93");
    assert(toHex("abcdefghijklmnopqrst") == "46253419B66D21A89EB473281FCB5D54");
    assert(toHex("abcdefghijklmnopqrstu") == "0DF3C0A62086736C0D59B9E7998D082E");
    assert(toHex("abcdefghijklmnopqrstuv") == "D921D4A7EADC5C09A9BB3C3984233408");
    assert(toHex("abcdefghijklmnopqrstuvw") == "573DA9C34949012B7EAD7B318F1509E8");
    assert(toHex("abcdefghijklmnopqrstuvwx") == "D7812380378356794971F89101486E32");
    assert(toHex("abcdefghijklmnopqrstuvwxy") == "A519C60A751523304AD7805A42A8FADE");
    assert(toHex("abcdefghijklmnopqrstuvwxyz") == "3E340613666F2F6617F6566E44E33D2C");

    // Pushing pieces shorter than block size.
    auto hasher = MurmurHash3_x86_128();
    hasher.put(['a', 'b']);
    hasher.put(['c', 'd']);
    assert(hasher.finish().toHex() == "96B6CCAA45AFC62E45AFC62E45AFC62E");
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
    enum blockSizeInBytes = Block.sizeof;
    enum ulong c1 = 0x87c37b91114253d5;
    enum ulong c2 = 0x4cf5ad432745937f;
    ulong h2, h1;
    size_t size;

public:
    alias Block = ulong[2];

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

    void putBlocks(scope const(Block)[] blocks...) pure nothrow @nogc
    {
        foreach (block; blocks)
        {
            update(h1, block[0], h2, c1, c2, 31, 27, 0x52dce729);
            update(h2, block[1], h1, c2, c1, 33, 31, 0x38495ab5);
        }
        size += blocks.length * Block.sizeof;
    }

    void putRemainder(scope const(ubyte)[] data...) pure nothrow @nogc
    {
        assert(data.length < blockSizeInBytes);
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
        return [h2, h1];
    }

    ubyte[16] getBytes() pure nothrow @nogc
    {
        return cast(ubyte[16])get();
    }
}

unittest
{
    alias toHex = digestToHex!MurmurHash3_x64_128;
    assert(toHex("") == "00000000000000000000000000000000");
    assert(toHex("a") == "85555565F6597889E6B53A48510E895A");
    assert(toHex("ab") == "938B11EA16ED1B2EE65EA7019B52D4AD");
    assert(toHex("abc") == "B4963F3F3FAD78673BA2744126CA2D52");
    assert(toHex("abcd") == "B87BB7D64656CD4FF2003E886073E875");
    assert(toHex("abcde") == "2036D091F496BBB8C5C7EEA04BCFEC8C");
    assert(toHex("abcdef") == "E47D86BFACA3BF55B07109993321845C");
    assert(toHex("abcdefg") == "A6CD2F9FC09EE4991C3AA23AB155BBB6");
    assert(toHex("abcdefgh") == "CC8A0AB037EF8C0248890D60EB6940A1");
    assert(toHex("abcdefghi") == "0547C0CFF13C796479B53DF5B741E033");
    assert(toHex("abcdefghij") == "B6C15B0D772F8C99A24D85DC8C651AC9");
    assert(toHex("abcdefghijk") == "A895D0B8DF789D02BB7C31E2455AE771");
    assert(toHex("abcdefghijkl") == "8EF39BB1E67AE1941F9E303272FF621C");
    assert(toHex("abcdefghijklm") == "1648288DA7C0FA732E657BFF0DE7CC7F");
    assert(toHex("abcdefghijklmn") == "91D094A7F5C375E0EE096027D26A3324");
    assert(toHex("abcdefghijklmno") == "8ABE2451890C2FFB6A548C2D9C962A61");
    assert(toHex("abcdefghijklmnop") == "C4CA3CA3224CB7234333D695B331EB1A");
    assert(toHex("abcdefghijklmnopq") == "7564747F88BDA657ECDA499DA1110DE4");
    assert(toHex("abcdefghijklmnopqr") == "77F08CEC907F8A5071D4A8295A00C76B");
    assert(toHex("abcdefghijklmnopqrs") == "1590BC23DE9E6D88A68A4D2AB66F9474");
    assert(toHex("abcdefghijklmnopqrst") == "310B3726F937E2F19609F42A5716D04B");
    assert(toHex("abcdefghijklmnopqrstu") == "C9D568E279FFC93CD7CC48C1E99B3CFB");
    assert(toHex("abcdefghijklmnopqrstuv") == "9588E330F4ABF85646DB1F74A8F4A96D");
    assert(toHex("abcdefghijklmnopqrstuvw") == "40480ABA9D4F238E83BEB7EB1C54E9FF");
    assert(toHex("abcdefghijklmnopqrstuvwx") == "6494960FD4DE2CF7790FCFA35321F208");
    assert(toHex("abcdefghijklmnopqrstuvwxy") == "71E7CBA42F07960FEDEE1581399EBDDB");
    assert(toHex("abcdefghijklmnopqrstuvwxyz") == "749C9D7E516F4AA9E9AD9C89B6A7D529");

    // Pushing pieces shorter than block size.
    auto hasher = MurmurHash3_x64_128();
    hasher.put(['a', 'b']);
    hasher.put(['c', 'd']);
    assert(hasher.finish().toHex() == "B87BB7D64656CD4FF2003E886073E875");
}

unittest
{
    // Pushing unaligned data and making sure the result is still coherent.
    void testUnalignedHash(H)() {
        immutable ubyte[1025] data = 0xAC;
        immutable alignedHash = digest!H(data[0..$-1]); // 0..1023
        immutable unalignedHash = digest!H(data[1..$]); // 1..1024
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
