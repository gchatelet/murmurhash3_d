import std.traits : isUnsigned;

@safe:

struct Digester(T)
{
    T instance;
    void start()
    {
        instance = T();
    }

    ubyte[T.blockSize] finish()
    {
        instance.finalize();
        return cast(ubyte[T.blockSize])(instance.get());
    }

    void put(scope const(ubyte)[] data...)
    {
        instance.put(data);
    }
}

alias MurmurHash3_x86_32 = Digester!SMurmurHash3_x86_32;
alias MurmurHash3_x86_128 = Digester!SMurmurHash3_x86_128;
alias MurmurHash3_x64_128 = Digester!SMurmurHash3_x64_128;

struct SMurmurHash3_x86_32
{
private:
    enum blockSize = uint.sizeof;
    enum uint c1 = 0xcc9e2d51;
    enum uint c2 = 0x1b873593;
    uint h1;
    size_t size;

    @disable this(this);

    this(uint seed = 0)
    {
        h1 = seed;
    }

public:

    void put(uint value)
    {
        update(h1, value, 0, c1, c2, 15, 13, 0xe6546b64);
        size += value.sizeof;
    }

    void put(scope const(ubyte)[] data...)
    {
        for (; data.length >= blockSize; data = data[blockSize .. $])
        {
            put((cast(const uint[]) data[0 .. blockSize])[0]);
        }
        size += data.length;
        uint k1 = 0;
        final switch (data.length & 3)
        {
        case 3:
            k1 ^= data[2] << 16;
        case 2:
            k1 ^= data[1] << 8;
        case 1:
            k1 ^= data[0];
            h1 ^= shuffle(k1, c1, c2, 15);
        case 0:
        }
    }

    void finalize()
    {
        h1 ^= size;
        h1 = fmix(h1);
    }

    ubyte[4] get()
    {
        uint[1] tmp = [h1];
        return cast(ubyte[4]) tmp;
    }
}

version (unittest)
{
    import std.digest.digest;
    import std.string : representation;

    string digestToHex(T)(string data, uint seed = 0)
    {
        return digest!(T)(data).toHexString!(Order.decreasing).idup;
    }
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
}

struct SMurmurHash3_x86_128
{
private:
    alias uint4 = uint[4];
    enum blockSize = uint4.sizeof;
    enum uint c1 = 0x239b961b;
    enum uint c2 = 0xab0e9789;
    enum uint c3 = 0x38b34ae5;
    enum uint c4 = 0xa1e38b93;
    uint h4, h3, h2, h1;
    size_t size;

    @disable this(this);
    this(uint seed4, uint seed3, uint seed2, uint seed1)
    {
        h4 = seed4;
        h3 = seed3;
        h2 = seed2;
        h1 = seed1;
    }

    this(uint seed = 0)
    {
        h4 = h3 = h2 = h1 = seed;
    }

public:

    void put(uint4 value)
    {
        update(h1, value[0], h2, c1, c2, 15, 19, 0x561ccd1b);
        update(h2, value[1], h3, c2, c3, 16, 17, 0x0bcaa747);
        update(h3, value[2], h4, c3, c4, 17, 15, 0x96cd1c35);
        update(h4, value[3], h1, c4, c1, 18, 13, 0x32ac3b17);
        size += value.sizeof;
    }

    void put(scope const(ubyte)[] data...)
    {
        for (; data.length >= blockSize; data = data[blockSize .. $])
        {
            put(cast(uint4) data[0 .. blockSize]);
        }
        size += data.length;
        uint k1 = 0;
        uint k2 = 0;
        uint k3 = 0;
        uint k4 = 0;

        final switch (data.length & 15)
        {
        case 15:
            k4 ^= data[14] << 16;
        case 14:
            k4 ^= data[13] << 8;
        case 13:
            k4 ^= data[12] << 0;
            h4 ^= shuffle(k4, c4, c1, 18);
        case 12:
            k3 ^= data[11] << 24;
        case 11:
            k3 ^= data[10] << 16;
        case 10:
            k3 ^= data[9] << 8;
        case 9:
            k3 ^= data[8] << 0;
            h3 ^= shuffle(k3, c3, c4, 17);
        case 8:
            k2 ^= data[7] << 24;
        case 7:
            k2 ^= data[6] << 16;
        case 6:
            k2 ^= data[5] << 8;
        case 5:
            k2 ^= data[4] << 0;
            h2 ^= shuffle(k2, c2, c3, 16);
        case 4:
            k1 ^= data[3] << 24;
        case 3:
            k1 ^= data[2] << 16;
        case 2:
            k1 ^= data[1] << 8;
        case 1:
            k1 ^= data[0] << 0;
            h1 ^= shuffle(k1, c1, c2, 15);
        case 0:
        }
    }

    void finalize()
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

    uint4 get()
    {
        return [h4, h3, h2, h1];
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
}

struct SMurmurHash3_x64_128
{
private:
    alias ulong2 = ulong[2];
    enum blockSize = ulong2.sizeof;
    enum ulong c1 = 0x87c37b91114253d5;
    enum ulong c2 = 0x4cf5ad432745937f;
    ulong h2, h1;
    size_t size;

    @disable this(this);
    this(ulong seed2, ulong seed1)
    {
        h2 = seed2;
        h1 = seed1;
    }

    this(ulong seed = 0)
    {
        h2 = h1 = seed;
    }

public:

    void put(ulong2 value)
    {
        update(h1, value[0], h2, c1, c2, 31, 27, 0x52dce729);
        update(h2, value[1], h1, c2, c1, 33, 31, 0x38495ab5);
        size += value.sizeof;
    }

    void put(scope const(ubyte)[] data...)
    {
        for (; data.length >= blockSize; data = data[blockSize .. $])
        {
            put(cast(ulong2) data[0 .. blockSize]);
        }
        size += data.length;
        ulong k1 = 0;
        ulong k2 = 0;
        final switch (data.length & 15)
        {
        case 15:
            k2 ^= ulong(data[14]) << 48;
        case 14:
            k2 ^= ulong(data[13]) << 40;
        case 13:
            k2 ^= ulong(data[12]) << 32;
        case 12:
            k2 ^= ulong(data[11]) << 24;
        case 11:
            k2 ^= ulong(data[10]) << 16;
        case 10:
            k2 ^= ulong(data[9]) << 8;
        case 9:
            k2 ^= ulong(data[8]) << 0;
            h2 ^= shuffle(k2, c2, c1, 33);
        case 8:
            k1 ^= ulong(data[7]) << 56;
        case 7:
            k1 ^= ulong(data[6]) << 48;
        case 6:
            k1 ^= ulong(data[5]) << 40;
        case 5:
            k1 ^= ulong(data[4]) << 32;
        case 4:
            k1 ^= ulong(data[3]) << 24;
        case 3:
            k1 ^= ulong(data[2]) << 16;
        case 2:
            k1 ^= ulong(data[1]) << 8;
        case 1:
            k1 ^= ulong(data[0]) << 0;
            h1 ^= shuffle(k1, c1, c2, 31);
        case 0:
        };
    }

    void finalize()
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

    ulong2 get()
    {
        return [h2, h1];
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
}

private:
template bits(T)
{
    enum bits = T.sizeof * 8;
}

T rotl(T)(T x, uint y) if (isUnsigned!T)
in
{
    assert(y >= 0 && y <= bits!T);
}
body
{
    return ((x << y) | (x >> (bits!T - y)));
}

T shuffle(T)(T k, T c1, T c2, ubyte r1) if (isUnsigned!T)
{
    k *= c1;
    k = rotl(k, r1);
    k *= c2;
    return k;
}

void update(T)(ref T h, T k, T mixWith, T c1, T c2, ubyte r1, ubyte r2, T n)
{
    h ^= shuffle(k, c1, c2, r1);
    h = rotl(h, r2);
    h += mixWith;
    h = h * 5 + n;
}

uint fmix(uint h)
{
    h ^= h >> 16;
    h *= 0x85ebca6b;
    h ^= h >> 13;
    h *= 0xc2b2ae35;
    h ^= h >> 16;
    return h;
}

ulong fmix(ulong k)
{
    k ^= k >> 33;
    k *= 0xff51afd7ed558ccd;
    k ^= k >> 33;
    k *= 0xc4ceb9fe1a85ec53;
    k ^= k >> 33;
    return k;
}

// @system void main()
// {
//     import std.stdio : stdin;
//     import std.digest.digest;
//
//     auto stdinRange = stdin.byChunk(64 * 1024);
//     writeln(digest!MurmurHash3_x64_128(stdinRange).toHexString!(Order.decreasing)());
// }
