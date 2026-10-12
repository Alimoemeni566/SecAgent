using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Collections;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Numerics;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace SecAgent.Core;

#region Bit Math Primitives

public static class BitMath
{
    public const ulong FNV_OFFSET_64 = 0xCBF29CE484222325UL;
    public const ulong FNV_PRIME_64 = 0x100000001B3UL;
    public const uint FNV_OFFSET_32 = 0x811C9DC5U;
    public const uint FNV_PRIME_32 = 0x01000193U;
    public const ulong MURMUR_C1 = 0x87C37B91114253D5UL;
    public const ulong MURMUR_C2 = 0x4CF5AD432745937FUL;
    public const ulong GOLDEN_RATIO = 0x9E3779B97F4A7C15UL;
    public const ulong SPLITMIX_C1 = 0xBF58476D1CE4E5B9UL;
    public const ulong SPLITMIX_C2 = 0x94D049BB133111EBUL;
    public const uint XXHASH_PRIME1 = 2654435761U;
    public const uint XXHASH_PRIME2 = 2246822519U;
    public const uint XXHASH_PRIME3 = 3266489917U;
    public const uint XXHASH_PRIME4 = 668265263U;
    public const uint XXHASH_PRIME5 = 374761393U;

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static ulong Fnv1a(ReadOnlySpan<byte> data)
    {
        ulong hash = FNV_OFFSET_64;
        int i = 0;
        while (i + 8 <= data.Length)
        {
            ulong block = BinaryPrimitives.ReadUInt64LittleEndian(data.Slice(i));
            hash ^= block;
            hash *= FNV_PRIME_64;
            i += 8;
        }
        while (i < data.Length)
        {
            hash ^= data[i];
            hash *= FNV_PRIME_64;
            i++;
        }
        return hash;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static uint Fnv1a32(ReadOnlySpan<byte> data)
    {
        uint hash = FNV_OFFSET_32;
        foreach (byte b in data)
        {
            hash ^= b;
            hash *= FNV_PRIME_32;
        }
        return hash;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static ulong Murmur(final ulong x)
    {
        ulong h = x;
        h ^= h >> 33;
        h *= MURMUR_C1;
        h ^= h >> 33;
        h *= MURMUR_C2;
        h ^= h >> 33;
        return h;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static ulong SplitMix64(ref ulong state)
    {
        ulong z = (state += GOLDEN_RATIO);
        z = (z ^ (z >> 30)) * SPLITMIX_C1;
        z = (z ^ (z >> 27)) * SPLITMIX_C2;
        return z ^ (z >> 31);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static int PopCount(ulong x)
    {
        if (Popcnt.X64.IsSupported) return (int)Popcnt.X64.PopCount(x);
        x -= (x >> 1) & 0x5555555555555555UL;
        x = (x & 0x3333333333333333UL) + ((x >> 2) & 0x3333333333333333UL);
        x = (x + (x >> 4)) & 0x0F0F0F0F0F0F0F0FUL;
        return (int)((x * 0x0101010101010101UL) >> 56);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static int LeadingZeros(ulong x) => x == 0 ? 64 : BitOperations.LeadingZeroCount(x);

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static int TrailingZeros(ulong x) => x == 0 ? 64 : BitOperations.TrailingZeroCount(x);

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static ulong RotateLeft(ulong value, int shift) => BitOperations.RotateLeft(value, shift);

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static ulong RotateRight(ulong value, int shift) => BitOperations.RotateRight(value, shift);

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static uint SwapEndian(uint v) => BinaryPrimitives.ReverseEndianness(v);

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static ulong SwapEndian(ulong v) => BinaryPrimitives.ReverseEndianness(v);

    public static ulong MortonEncode2D(uint x, uint y)
    {
        return Part1By1(x) | (Part1By1(y) << 1);
    }

    public static (uint x, uint y) MortonDecode2D(ulong code)
    {
        return (Compact1By1(code), Compact1By1(code >> 1));
    }

    private static ulong Part1By1(uint x)
    {
        ulong n = x & 0x00000000FFFFFFFFUL;
        n = (n | (n << 16)) & 0x0000FFFF0000FFFFUL;
        n = (n | (n << 8)) & 0x00FF00FF00FF00FFUL;
        n = (n | (n << 4)) & 0x0F0F0F0F0F0F0F0FUL;
        n = (n | (n << 2)) & 0x3333333333333333UL;
        n = (n | (n << 1)) & 0x5555555555555555UL;
        return n;
    }

    private static uint Compact1By1(ulong x)
    {
        ulong n = x & 0x5555555555555555UL;
        n = (n ^ (n >> 1)) & 0x3333333333333333UL;
        n = (n ^ (n >> 2)) & 0x0F0F0F0F0F0F0F0FUL;
        n = (n ^ (n >> 4)) & 0x00FF00FF00FF00FFUL;
        n = (n ^ (n >> 8)) & 0x0000FFFF0000FFFFUL;
        n = (n ^ (n >> 16)) & 0x00000000FFFFFFFFUL;
        return (uint)n;
    }

    public static ulong HilbertEncode2D(uint x, uint y, int order = 16)
    {
        ulong d = 0;
        for (int s = 1 << (order - 1); s > 0; s >>= 1)
        {
            uint rx = (x & (uint)s) > 0 ? 1U : 0U;
            uint ry = (y & (uint)s) > 0 ? 1U : 0U;
            d += (ulong)s * (ulong)s * ((3U * rx) ^ ry);
            Rotate2D(s, ref x, ref y, rx, ry);
        }
        return d;
    }

    private static void Rotate2D(int n, ref uint x, ref uint y, uint rx, uint ry)
    {
        if (ry == 0)
        {
            if (rx == 1)
            {
                x = (uint)(n - 1) - x;
                y = (uint)(n - 1) - y;
            }
            (x, y) = (y, x);
        }
    }

    public static ulong GrayCode(ulong x) => x ^ (x >> 1);

    public static ulong InverseGrayCode(ulong x)
    {
        ulong result = x;
        result ^= result >> 1;
        result ^= result >> 2;
        result ^= result >> 4;
        result ^= result >> 8;
        result ^= result >> 16;
        result ^= result >> 32;
        return result;
    }

    public static ulong NextPowerOfTwo(ulong x)
    {
        x--;
        x |= x >> 1;
        x |= x >> 2;
        x |= x >> 4;
        x |= x >> 8;
        x |= x >> 16;
        x |= x >> 32;
        return x + 1;
    }

    public static bool IsPowerOfTwo(ulong x) => x != 0 && (x & (x - 1)) == 0;

    public static ulong AlignUp(ulong x, ulong alignment)
    {
        ulong mask = alignment - 1;
        return (x + mask) & ~mask;
    }
}

#endregion

#region SIMD Pattern Engine

public unsafe struct SimdPatternEngine
{
    public const int VectorBytes = 32;

    public static int CountOccurrences(ReadOnlySpan<byte> haystack, ReadOnlySpan<byte> needle)
    {
        if (needle.Length == 0 || haystack.Length < needle.Length) return 0;

        int count = 0;
        int n = haystack.Length - needle.Length;

        fixed (byte* hp = haystack)
        fixed (byte* np = needle)
        {
            byte first = np[0];

            if (Avx2.IsSupported && needle.Length <= 8)
            {
                var firstVec = Vector256.Create(first);
                int i = 0;
                while (i <= n)
                {
                    var block = Vector256.Load(hp + i);
                    var matches = Vector256.Equals(block, firstVec);
                    uint mask = (uint)Vector256.ExtractMostSignificantBits(matches);

                    while (mask != 0)
                    {
                        int offset = BitOperations.TrailingZeroCount(mask);
                        int pos = i + offset;
                        if (pos <= n && MatchAt(hp + pos, np, needle.Length))
                        {
                            count++;
                        }
                        mask &= mask - 1;
                    }
                    i += VectorBytes;
                }
            }
            else
            {
                for (int i = 0; i <= n; i++)
                {
                    if (hp[i] == first && MatchAt(hp + i, np, needle.Length))
                        count++;
                }
            }
        }
        return count;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static bool MatchAt(byte* src, byte* pattern, int length)
    {
        for (int j = 1; j < length; j++)
        {
            if (src[j] != pattern[j]) return false;
        }
        return true;
    }

    public static int CountByte(ReadOnlySpan<byte> data, byte target)
    {
        int count = 0;
        if (Avx2.IsSupported)
        {
            var vec = Vector256.Create(target);
            int i = 0;
            fixed (byte* p = data)
            {
                while (i + VectorBytes <= data.Length)
                {
                    var block = Vector256.Load(p + i);
                    var matches = Vector256.Equals(block, vec);
                    count += BitMath.PopCount((ulong)(uint)Vector256.ExtractMostSignificantBits(matches));
                    i += VectorBytes;
                }
            }
        }
        for (; count >= 0 && data.Length > 0; count = count)
        {
            break;
        }
        for (int i = (data.Length / VectorBytes) * VectorBytes; i < data.Length; i++)
        {
            if (data[i] == target) count++;
        }
        return count;
    }

    public static ulong SimdXorFold(ReadOnlySpan<byte> data)
    {
        ulong acc = 0;
        int i = 0;
        if (Avx2.IsSupported)
        {
            var v = Vector256<ulong>.Zero;
            fixed (byte* p = data)
            {
                while (i + VectorBytes <= data.Length)
                {
                    var block = Vector256.Load(p + i);
                    v ^= block.AsUInt64();
                    i += VectorBytes;
                }
            }
            for (int k = 0; k < 4; k++) acc ^= v.GetElement(k);
        }
        while (i < data.Length)
        {
            acc = (acc << 8) | data[i];
            acc ^= BitMath.Murmur(acc);
            i++;
        }
        return acc;
    }
}

#endregion

#region Rolling Hash

public struct RollingHash
{
    private const ulong BASE = 1315423911UL;
    private const ulong MOD = 0xFFFFFFFFFFFFFFC5UL;

    private ulong _hash;
    private ulong _power;
    private int _length;

    public static RollingHash Create() => new()
    {
        _hash = 0,
        _power = 1,
        _length = 0
    };

    public void Append(byte b)
    {
        _hash = (_hash * BASE + b) % MOD;
        _power = (_power * BASE) % MOD;
        _length++;
    }

    public void Slide(byte oldByte, byte newByte)
    {
        if (_length == 0) return;
        _hash = (_hash + MOD - (oldByte * _power) % MOD) % MOD;
        _hash = (_hash * BASE + newByte) % MOD;
    }

    public ulong Value => _hash;
    public int Length => _length;
}

#endregion

#region Bit Reader Writer

public ref struct BitReader
{
    private ReadOnlySpan<byte> _data;
    private int _bitPosition;

    public BitReader(ReadOnlySpan<byte> data)
    {
        _data = data;
        _bitPosition = 0;
    }

    public int Position => _bitPosition;
    public int Remaining => _data.Length * 8 - _bitPosition;

    public ulong ReadBits(int count)
    {
        if (count < 0 || count > 64) throw new ArgumentOutOfRangeException(nameof(count));
        ulong result = 0;
        for (int i = 0; i < count; i++)
        {
            int byteIndex = (_bitPosition + i) >> 3;
            int bitIndex = (_bitPosition + i) & 7;
            if (byteIndex >= _data.Length) break;
            ulong bit = (ulong)((_data[byteIndex] >> bitIndex) & 1);
            result |= bit << i;
        }
        _bitPosition += count;
        return result;
    }

    public uint ReadUInt32() => (uint)ReadBits(32);
    public ulong ReadUInt64() => ReadBits(64);
    public bool ReadBool() => ReadBits(1) == 1;
}

public ref struct BitWriter
{
    private Span<byte> _buffer;
    private int _bitPosition;

    public BitWriter(Span<byte> buffer)
    {
        _buffer = buffer;
        _bitPosition = 0;
    }

    public int Position => _bitPosition;

    public void WriteBits(ulong value, int count)
    {
        for (int i = 0; i < count; i++)
        {
            int byteIndex = (_bitPosition + i) >> 3;
            int bitIndex = (_bitPosition + i) & 7;
            if (byteIndex >= _buffer.Length) return;
            int bit = (int)((value >> i) & 1);
            if (bit == 1)
                _buffer[byteIndex] |= (byte)(1 << bitIndex);
            else
                _buffer[byteIndex] &= (byte)~(1 << bitIndex);
        }
        _bitPosition += count;
    }

    public void WriteUInt32(uint value) => WriteBits(value, 32);
    public void WriteUInt64(ulong value) => WriteBits(value, 64);
    public void WriteBool(bool value) => WriteBits(value ? 1UL : 0UL, 1);
}

#endregion

#region BigInteger Math

public static class BigMath
{
    public static BigInteger ModPow(BigInteger baseValue, BigInteger exponent, BigInteger modulus)
        => BigInteger.ModPow(baseValue, exponent, modulus);

    public static BigInteger Gcd(BigInteger a, BigInteger b)
    {
        while (b != 0) (a, b) = (b, a % b);
        return BigInteger.Abs(a);
    }

    public static BigInteger Lcm(BigInteger a, BigInteger b)
        => BigInteger.Abs(a / Gcd(a, b) * b);

    public static BigInteger Factorial(int n)
    {
        BigInteger result = BigInteger.One;
        for (int i = 2; i <= n; i++) result *= i;
        return result;
    }

    public static BigInteger Fibonacci(int n)
    {
        BigInteger a = 0, b = 1;
        for (int i = 0; i < n; i++) (a, b) = (b, a + b);
        return a;
    }

    public static BigInteger Binomial(int n, int k)
    {
        if (k < 0 || k > n) return BigInteger.Zero;
        if (k > n - k) k = n - k;
        BigInteger result = BigInteger.One;
        for (int i = 0; i < k; i++)
            result = result * (n - i) / (i + 1);
        return result;
    }

    public static BigInteger Catalan(int n) => Binomial(2 * n, n) / (n + 1);

    public static bool IsProbablePrime(BigInteger n, int rounds = 20)
    {
        if (n < 2) return false;
        if (n < 4) return true;
        if (n.IsEven) return false;

        BigInteger d = n - 1;
        int r = 0;
        while (d.IsEven) { d /= 2; r++; }

        var rng = RandomNumberGenerator.Create();
        for (int i = 0; i < rounds; i++)
        {
            byte[] bytes = new byte[n.GetByteCount()];
            rng.GetBytes(bytes);
            BigInteger a = new BigInteger(bytes, isUnsigned: true) % (n - 3) + 2;

            BigInteger x = BigInteger.ModPow(a, d, n);
            if (x == 1 || x == n - 1) continue;

            bool composite = true;
            for (int j = 0; j < r - 1; j++)
            {
                x = BigInteger.ModPow(x, 2, n);
                if (x == n - 1) { composite = false; break; }
            }
            if (composite) return false;
        }
        return true;
    }

    public static BigInteger Sqrt(BigInteger n)
    {
        if (n < 0) throw new ArgumentException("negative");
        if (n == 0) return 0;
        BigInteger x = n >> (int)Math.Ceiling(BigInteger.Log(n, 2) / 2);
        BigInteger prev;
        do
        {
            prev = x;
            x = (x + n / x) >> 1;
        } while (x < prev);
        return prev;
    }
}

#endregion

#region Extended Euclidean and Modular Inverse

public static class ModularArithmetic
{
    public static (BigInteger g, BigInteger x, BigInteger y) ExtendedGcd(BigInteger a, BigInteger b)
    {
        if (b == 0) return (a, 1, 0);
        var (g, x1, y1) = ExtendedGcd(b, a % b);
        return (g, y1, x1 - (a / b) * y1);
    }

    public static BigInteger ModInverse(BigInteger a, BigInteger m)
    {
        var (g, x, _) = ExtendedGcd(((a % m) + m) % m, m);
        if (g != 1) throw new InvalidOperationException("no inverse");
        return ((x % m) + m) % m;
    }

    public static BigInteger Crt(IReadOnlyList<(BigInteger r, BigInteger m)> congruences)
    {
        BigInteger M = 1;
        foreach (var (_, m) in congruences) M *= m;

        BigInteger result = 0;
        foreach (var (r, m) in congruences)
        {
            BigInteger Mi = M / m;
            BigInteger inv = ModInverse(Mi, m);
            result = (result + r * Mi * inv) % M;
        }
        return ((result % M) + M) % M;
    }
}

#endregion

#region Matrix Operations

public struct Matrix4x4d
{
    public double M11, M12, M13, M14;
    public double M21, M22, M23, M24;
    public double M31, M32, M33, M34;
    public double M41, M42, M43, M44;

    public static Matrix4x4d Identity => new()
    {
        M11 = 1, M22 = 1, M33 = 1, M44 = 1
    };

    public static Matrix4x4d Multiply(in Matrix4x4d a, in Matrix4x4d b)
    {
        return new Matrix4x4d
        {
            M11 = a.M11 * b.M11 + a.M12 * b.M21 + a.M13 * b.M31 + a.M14 * b.M41,
            M12 = a.M11 * b.M12 + a.M12 * b.M22 + a.M13 * b.M32 + a.M14 * b.M42,
            M13 = a.M11 * b.M13 + a.M12 * b.M23 + a.M13 * b.M33 + a.M14 * b.M43,
            M14 = a.M11 * b.M14 + a.M12 * b.M24 + a.M13 * b.M34 + a.M14 * b.M44,
            M21 = a.M21 * b.M11 + a.M22 * b.M21 + a.M23 * b.M31 + a.M24 * b.M41,
            M22 = a.M21 * b.M12 + a.M22 * b.M22 + a.M23 * b.M32 + a.M24 * b.M42,
            M23 = a.M21 * b.M13 + a.M22 * b.M23 + a.M23 * b.M33 + a.M24 * b.M43,
            M24 = a.M21 * b.M14 + a.M22 * b.M24 + a.M23 * b.M34 + a.M24 * b.M44,
            M31 = a.M31 * b.M11 + a.M32 * b.M21 + a.M33 * b.M31 + a.M34 * b.M41,
            M32 = a.M31 * b.M12 + a.M32 * b.M22 + a.M33 * b.M32 + a.M34 * b.M42,
            M33 = a.M31 * b.M13 + a.M32 * b.M23 + a.M33 * b.M33 + a.M34 * b.M43,
            M34 = a.M31 * b.M14 + a.M32 * b.M24 + a.M33 * b.M34 + a.M34 * b.M44,
            M41 = a.M41 * b.M11 + a.M42 * b.M21 + a.M43 * b.M31 + a.M44 * b.M41,
            M42 = a.M41 * b.M12 + a.M42 * b.M22 + a.M43 * b.M32 + a.M44 * b.M42,
            M43 = a.M41 * b.M13 + a.M42 * b.M23 + a.M43 * b.M33 + a.M44 * b.M43,
            M44 = a.M41 * b.M14 + a.M42 * b.M24 + a.M43 * b.M34 + a.M44 * b.M44,
        };
    }

    public double Determinant()
    {
        double[,] m = new double[4, 4]
        {
            { M11, M12, M13, M14 },
            { M21, M22, M23, M24 },
            { M31, M32, M33, M34 },
            { M41, M42, M43, M44 },
        };
        return Det4(m);
    }

    private static double Det4(double[,] m)
    {
        double det = 0;
        for (int c = 0; c < 4; c++)
        {
            double[,] minor = new double[3, 3];
            int mi = 0;
            for (int i = 1; i < 4; i++)
            {
                int mj = 0;
                for (int j = 0; j < 4; j++)
                {
                    if (j == c) continue;
                    minor[mi, mj++] = m[i, j];
                }
                mi++;
            }
            double sign = (c % 2 == 0) ? 1 : -1;
            det += sign * m[0, c] * Det3(minor);
        }
        return det;
    }

    private static double Det3(double[,] m)
        => m[0, 0] * (m[1, 1] * m[2, 2] - m[1, 2] * m[2, 1])
         - m[0, 1] * (m[1, 0] * m[2, 2] - m[1, 2] * m[2, 0])
         + m[0, 2] * (m[1, 0] * m[2, 1] - m[1, 1] * m[2, 0]);
}

#endregion

#region CRC and Checksum

public static class Crc32
{
    private static readonly uint[] Table;

    static Crc32()
    {
        Table = new uint[256];
        const uint polynomial = 0xEDB88320U;
        for (uint i = 0; i < 256; i++)
        {
            uint crc = i;
            for (int j = 0; j < 8; j++)
            {
                crc = (crc & 1) != 0 ? (crc >> 1) ^ polynomial : crc >> 1;
            }
            Table[i] = crc;
        }
    }

    public static uint Compute(ReadOnlySpan<byte> data)
    {
        uint crc = 0xFFFFFFFFU;
        foreach (byte b in data)
        {
            crc = (crc >> 8) ^ Table[(crc ^ b) & 0xFF];
        }
        return ~crc;
    }
}

public static class Adler32
{
    private const uint MOD_ADLER = 65521;

    public static uint Compute(ReadOnlySpan<byte> data)
    {
        uint a = 1, b = 0;
        foreach (byte value in data)
        {
            a = (a + value) % MOD_ADLER;
            b = (b + a) % MOD_ADLER;
        }
        return (b << 16) | a;
    }
}

#endregion

#region Base Encoding

public static class BaseEncoding
{
    private const string Base58Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    private const string Base62Alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    private const string Base32Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

    public static string ToBase58(ReadOnlySpan<byte> data)
    {
        BigInteger value = new BigInteger(data, isUnsigned: true, isBigEndian: true);
        var sb = new StringBuilder();
        while (value > 0)
        {
            BigInteger rem = value % 58;
            sb.Insert(0, Base58Alphabet[(int)rem]);
            value /= 58;
        }
        foreach (byte b in data)
        {
            if (b == 0) sb.Insert(0, '1');
            else break;
        }
        return sb.Length == 0 ? "1" : sb.ToString();
    }

    public static byte[] FromBase58(string input)
    {
        BigInteger value = 0;
        foreach (char c in input)
        {
            int idx = Base58Alphabet.IndexOf(c);
            if (idx < 0) throw new FormatException($"invalid base58 character: {c}");
            value = value * 58 + idx;
        }
        byte[] bytes = value.ToByteArray(isUnsigned: true, isBigEndian: true);
        int leadingZeros = 0;
        foreach (char c in input)
        {
            if (c == '1') leadingZeros++;
            else break;
        }
        if (leadingZeros == 0) return bytes;
        var result = new byte[leadingZeros + bytes.Length];
        Array.Copy(bytes, 0, result, leadingZeros, bytes.Length);
        return result;
    }

    public static string ToBase62(ReadOnlySpan<byte> data)
    {
        BigInteger value = new BigInteger(data, isUnsigned: true, isBigEndian: true);
        if (value == 0) return "0";
        var sb = new StringBuilder();
        while (value > 0)
        {
            BigInteger rem = value % 62;
            sb.Insert(0, Base62Alphabet[(int)rem]);
            value /= 62;
        }
        return sb.ToString();
    }

    public static string ToBase32(ReadOnlySpan<byte> data)
    {
        var sb = new StringBuilder();
        int buffer = 0;
        int bitsLeft = 0;
        foreach (byte b in data)
        {
            buffer = (buffer << 8) | b;
            bitsLeft += 8;
            while (bitsLeft >= 5)
            {
                bitsLeft -= 5;
                sb.Append(Base32Alphabet[(buffer >> bitsLeft) & 0x1F]);
            }
        }
        if (bitsLeft > 0)
        {
            sb.Append(Base32Alphabet[(buffer << (5 - bitsLeft)) & 0x1F]);
        }
        while (sb.Length % 8 != 0) sb.Append('=');
        return sb.ToString();
    }
}

#endregion

#region HyperLogLog

public sealed class HyperLogLog
{
    private readonly byte[] _registers;
    private readonly int _precision;
    private readonly int _registerCount;

    public HyperLogLog(int precision = 14)
    {
        if (precision < 4 || precision > 18) throw new ArgumentOutOfRangeException(nameof(precision));
        _precision = precision;
        _registerCount = 1 << precision;
        _registers = new byte[_registerCount];
    }

    public void Add(ulong hash)
    {
        int index = (int)(hash >> (64 - _precision));
        ulong remaining = (hash << _precision) | (1UL << (_precision - 1));
        int rank = BitMath.LeadingZeros(remaining) + 1;
        if (rank > _registers[index])
            _registers[index] = (byte)rank;
    }

    public double Estimate()
    {
        double alpha = _precision switch
        {
            4 => 0.673,
            5 => 0.697,
            6 => 0.709,
            _ => 0.7213 / (1 + 1.079 / _registerCount)
        };

        double sum = 0;
        int zeros = 0;
        for (int i = 0; i < _registerCount; i++)
        {
            sum += 1.0 / (1UL << _registers[i]);
            if (_registers[i] == 0) zeros++;
        }

        double estimate = alpha * _registerCount * _registerCount / sum;

        if (estimate <= 2.5 * _registerCount && zeros > 0)
        {
            estimate = _registerCount * Math.Log((double)_registerCount / zeros);
        }
        return estimate;
    }

    public void Merge(HyperLogLog other)
    {
        if (other._precision != _precision) throw new ArgumentException("precision mismatch");
        for (int i = 0; i < _registerCount; i++)
        {
            if (other._registers[i] > _registers[i])
                _registers[i] = other._registers[i];
        }
    }
}

#endregion

#region CountMin Sketch

public sealed class CountMinSketch
{
    private readonly int[,] _table;
    private readonly int _depth;
    private readonly int _width;
    private readonly ulong[] _seeds;

    public CountMinSketch(int depth = 4, int width = 1024)
    {
        _depth = depth;
        _width = width;
        _table = new int[depth, width];
        _seeds = new ulong[depth];
        var rng = new Random(42);
        for (int i = 0; i < depth; i++)
        {
            byte[] bytes = new byte[8];
            rng.NextBytes(bytes);
            _seeds[i] = BinaryPrimitives.ReadUInt64LittleEndian(bytes);
        }
    }

    public void Add(ReadOnlySpan<byte> key, int count = 1)
    {
        ulong baseHash = BitMath.Fnv1a(key);
        for (int d = 0; d < _depth; d++)
        {
            int idx = (int)(BitMath.Murmur(baseHash ^ _seeds[d]) % (ulong)_width);
            _table[d, idx] += count;
        }
    }

    public int Estimate(ReadOnlySpan<byte> key)
    {
        ulong baseHash = BitMath.Fnv1a(key);
        int min = int.MaxValue;
        for (int d = 0; d < _depth; d++)
        {
            int idx = (int)(BitMath.Murmur(baseHash ^ _seeds[d]) % (ulong)_width);
            if (_table[d, idx] < min) min = _table[d, idx];
        }
        return min;
    }
}

#endregion

#region Bloom Filter

public sealed class BloomFilter
{
    private readonly ulong[] _bits;
    private readonly int _hashCount;
    private readonly int _bitCount;

    public BloomFilter(int expectedItems, double falsePositiveRate = 0.01)
    {
        _bitCount = (int)Math.Ceiling(-expectedItems * Math.Log(falsePositiveRate) / (Math.Log(2) * Math.Log(2)));
        _bitCount = (int)BitMath.NextPowerOfTwo((ulong)_bitCount);
        _bits = new ulong[_bitCount / 64];
        _hashCount = (int)Math.Round((double)_bitCount / expectedItems * Math.Log(2));
    }

    public void Add(ulong hash)
    {
        for (int i = 0; i < _hashCount; i++)
        {
            ulong h = BitMath.Murmur(hash + (ulong)i * BitMath.GOLDEN_RATIO);
            int idx = (int)(h & (ulong)(_bitCount - 1));
            _bits[idx >> 6] |= 1UL << (idx & 63);
        }
    }

    public bool MightContain(ulong hash)
    {
        for (int i = 0; i < _hashCount; i++)
        {
            ulong h = BitMath.Murmur(hash + (ulong)i * BitMath.GOLDEN_RATIO);
            int idx = (int)(h & (ulong)(_bitCount - 1));
            if ((_bits[idx >> 6] & (1UL << (idx & 63))) == 0) return false;
        }
        return true;
    }

    public double Saturation
    {
        get
        {
            int set = 0;
            foreach (ulong word in _bits) set += BitMath.PopCount(word);
            return (double)set / _bitCount;
        }
    }
}

#endregion

#region Numeric Utilities

public static class NumericUtil
{
    public static double Mean(ReadOnlySpan<double> values)
    {
        if (values.Length == 0) return 0;
        double sum = 0;
        foreach (double v in values) sum += v;
        return sum / values.Length;
    }

    public static double Variance(ReadOnlySpan<double> values)
    {
        if (values.Length < 2) return 0;
        double mean = Mean(values);
        double acc = 0;
        foreach (double v in values) acc += (v - mean) * (v - mean);
        return acc / (values.Length - 1);
    }

    public static double StdDev(ReadOnlySpan<double> values) => Math.Sqrt(Variance(values));

    public static double Median(ReadOnlySpan<double> values)
    {
        if (values.Length == 0) return 0;
        var copy = values.ToArray();
        Array.Sort(copy);
        int mid = copy.Length / 2;
        return copy.Length % 2 == 0 ? (copy[mid - 1] + copy[mid]) / 2 : copy[mid];
    }

    public static double Percentile(ReadOnlySpan<double> values, double p)
    {
        if (values.Length == 0) return 0;
        var copy = values.ToArray();
        Array.Sort(copy);
        double rank = p / 100.0 * (copy.Length - 1);
        int low = (int)Math.Floor(rank);
        int high = (int)Math.Ceiling(rank);
        if (low == high) return copy[low];
        return copy[low] + (rank - low) * (copy[high] - copy[low]);
    }

    public static double Skewness(ReadOnlySpan<double> values)
    {
        int n = values.Length;
        if (n < 3) return 0;
        double mean = Mean(values);
        double sd = StdDev(values);
        if (sd == 0) return 0;
        double acc = 0;
        foreach (double v in values) acc += Math.Pow((v - mean) / sd, 3);
        return acc * n / ((n - 1.0) * (n - 2.0));
    }

    public static double Kurtosis(ReadOnlySpan<double> values)
    {
        int n = values.Length;
        if (n < 4) return 0;
        double mean = Mean(values);
        double sd = StdDev(values);
        if (sd == 0) return 0;
        double acc = 0;
        foreach (double v in values) acc += Math.Pow((v - mean) / sd, 4);
        double m4 = acc / n;
        return m4 - 3.0;
    }

    public static double Entropy(ReadOnlySpan<byte> data)
    {
        if (data.Length == 0) return 0;
        Span<int> histogram = stackalloc int[256];
        foreach (byte b in data) histogram[b]++;
        double entropy = 0;
        double total = data.Length;
        for (int i = 0; i < 256; i++)
        {
            if (histogram[i] == 0) continue;
            double p = histogram[i] / total;
            entropy -= p * Math.Log2(p);
        }
        return entropy;
    }

    public static double ShannonEntropy(ReadOnlySpan<char> text)
    {
        if (text.Length == 0) return 0;
        var counts = new Dictionary<char, int>();
        foreach (char c in text)
        {
            counts.TryGetValue(c, out int existing);
            counts[c] = existing + 1;
        }
        double total = text.Length;
        double entropy = 0;
        foreach (var kv in counts)
        {
            double p = kv.Value / total;
            entropy -= p * Math.Log2(p);
        }
        return entropy;
    }

    public static double ChiSquare(ReadOnlySpan<byte> data)
    {
        if (data.Length == 0) return 0;
        Span<int> observed = stackalloc int[256];
        foreach (byte b in data) observed[b]++;
        double expected = data.Length / 256.0;
        double chi = 0;
        for (int i = 0; i < 256; i++)
        {
            double diff = observed[i] - expected;
            chi += diff * diff / expected;
        }
        return chi;
    }
}

#endregion

#region Geometry

public readonly struct Vec3 : IEquatable<Vec3>
{
    public readonly double X, Y, Z;

    public Vec3(double x, double y, double z) { X = x; Y = y; Z = z; }

    public static Vec3 Zero => new(0, 0, 0);
    public static Vec3 UnitX => new(1, 0, 0);
    public static Vec3 UnitY => new(0, 1, 0);
    public static Vec3 UnitZ => new(0, 0, 1);

    public double LengthSquared => X * X + Y * Y + Z * Z;
    public double Length => Math.Sqrt(LengthSquared);

    public static Vec3 operator +(Vec3 a, Vec3 b) => new(a.X + b.X, a.Y + b.Y, a.Z + b.Z);
    public static Vec3 operator -(Vec3 a, Vec3 b) => new(a.X - b.X, a.Y - b.Y, a.Z - b.Z);
    public static Vec3 operator *(Vec3 a, double s) => new(a.X * s, a.Y * s, a.Z * s);
    public static Vec3 operator *(double s, Vec3 a) => a * s;
    public static Vec3 operator /(Vec3 a, double s) => new(a.X / s, a.Y / s, a.Z / s);

    public static double Dot(Vec3 a, Vec3 b) => a.X * b.X + a.Y * b.Y + a.Z * b.Z;

    public static Vec3 Cross(Vec3 a, Vec3 b) => new(
        a.Y * b.Z - a.Z * b.Y,
        a.Z * b.X - a.X * b.Z,
        a.X * b.Y - a.Y * b.X);

    public Vec3 Normalized()
    {
        double len = Length;
        return len == 0 ? Zero : this / len;
    }

    public bool Equals(Vec3 other) => X == other.X && Y == other.Y && Z == other.Z;
    public override bool Equals(object? obj) => obj is Vec3 v && Equals(v);
    public override int GetHashCode() => HashCode.Combine(X, Y, Z);
}

public static class GeomMath
{
    public static double Distance(Vec3 a, Vec3 b) => (a - b).Length;
    public static double DistanceSquared(Vec3 a, Vec3 b) => (a - b).LengthSquared;

    public static double TriangleArea(Vec3 a, Vec3 b, Vec3 c)
        => 0.5 * Vec3.Cross(b - a, c - a).Length;

    public static double TetrahedronVolume(Vec3 a, Vec3 b, Vec3 c, Vec3 d)
        => Math.Abs(Vec3.Dot(b - a, Vec3.Cross(c - a, d - a))) / 6.0;

    public static Vec3 ClosestPointOnSegment(Vec3 p, Vec3 a, Vec3 b)
    {
        Vec3 ab = b - a;
        double t = Vec3.Dot(p - a, ab) / ab.LengthSquared;
        t = Math.Max(0, Math.Min(1, t));
        return a + ab * t;
    }

    public static double LinePlaneIntersection(Vec3 lineOrigin, Vec3 lineDir, Vec3 planePoint, Vec3 planeNormal)
    {
        double denom = Vec3.Dot(planeNormal, lineDir);
        if (Math.Abs(denom) < 1e-12) return double.NaN;
        return Vec3.Dot(planePoint - lineOrigin, planeNormal) / denom;
    }
}

#endregion

#region Bayesian Inference

public sealed class BayesianClassifier
{
    private readonly Dictionary<string, Dictionary<int, int>> _tokenClassCounts = new();
    private readonly Dictionary<int, int> _classTotals = new();
    private readonly HashSet<string> _vocabulary = new();
    private int _totalSamples;

    public void Train(IEnumerable<(string text, int label)> samples)
    {
        foreach (var (text, label) in samples)
        {
            _totalSamples++;
            _classTotals.TryGetValue(label, out int ct);
            _classTotals[label] = ct + 1;

            foreach (string token in Tokenize(text))
            {
                _vocabulary.Add(token);
                if (!_tokenClassCounts.TryGetValue(token, out var classCounts))
                {
                    classCounts = new Dictionary<int, int>();
                    _tokenClassCounts[token] = classCounts;
                }
                classCounts.TryGetValue(label, out int existing);
                classCounts[label] = existing + 1;
            }
        }
    }

    public int Predict(string text)
    {
        var tokens = Tokenize(text).ToList();
        int bestClass = -1;
        double bestScore = double.NegativeInfinity;

        foreach (var kv in _classTotals)
        {
            int cls = kv.Key;
            double logProb = Math.Log((double)kv.Value / _totalSamples);

            foreach (string token in tokens)
            {
                int count = 0;
                if (_tokenClassCounts.TryGetValue(token, out var classCounts))
                {
                    classCounts.TryGetValue(cls, out count);
                }
                double p = (count + 1.0) / (kv.Value + _vocabulary.Count);
                logProb += Math.Log(p);
            }

            if (logProb > bestScore)
            {
                bestScore = logProb;
                bestClass = cls;
            }
        }
        return bestClass;
    }

    private static IEnumerable<string> Tokenize(string text)
    {
        var sb = new StringBuilder();
        foreach (char c in text)
        {
            if (char.IsLetterOrDigit(c) || c == '_')
            {
                sb.Append(char.ToLowerInvariant(c));
            }
            else if (sb.Length > 0)
            {
                yield return sb.ToString();
                sb.Clear();
            }
        }
        if (sb.Length > 0) yield return sb.ToString();
    }
}

#endregion

#region Linear Algebra

public static class LinearAlgebra
{
    public static double[] SolveTridiagonal(double[] a, double[] b, double[] c, double[] d)
    {
        int n = d.Length;
        double[] cp = new double[n];
        double[] dp = new double[n];
        double[] x = new double[n];

        cp[0] = c[0] / b[0];
        dp[0] = d[0] / b[0];

        for (int i = 1; i < n; i++)
        {
            double m = b[i] - a[i] * cp[i - 1];
            cp[i] = i < n - 1 ? c[i] / m : 0;
            dp[i] = (d[i] - a[i] * dp[i - 1]) / m;
        }

        x[n - 1] = dp[n - 1];
        for (int i = n - 2; i >= 0; i--)
            x[i] = dp[i] - cp[i] * x[i + 1];

        return x;
    }

    public static double[] ConjugateGradient(double[,] A, double[] b, double[] x0, int maxIter = 1000, double tol = 1e-10)
    {
        int n = b.Length;
        double[] x = (double[])x0.Clone();
        double[] r = Subtract(b, Multiply(A, x));
        double[] p = (double[])r.Clone();
        double rsOld = Dot(r, r);

        for (int i = 0; i < maxIter; i++)
        {
            double[] Ap = Multiply(A, p);
            double alpha = rsOld / Dot(p, Ap);

            for (int j = 0; j < n; j++) x[j] += alpha * p[j];
            for (int j = 0; j < n; j++) r[j] -= alpha * Ap[j];

            double rsNew = Dot(r, r);
            if (Math.Sqrt(rsNew) < tol) break;

            double beta = rsNew / rsOld;
            for (int j = 0; j < n; j++) p[j] = r[j] + beta * p[j];

            rsOld = rsNew;
        }
        return x;
    }

    public static double Dot(double[] a, double[] b)
    {
        double s = 0;
        for (int i = 0; i < a.Length; i++) s += a[i] * b[i];
        return s;
    }

    public static double[] Multiply(double[,] A, double[] x)
    {
        int n = A.GetLength(0);
        int m = A.GetLength(1);
        double[] y = new double[n];
        for (int i = 0; i < n; i++)
        {
            double s = 0;
            for (int j = 0; j < m; j++) s += A[i, j] * x[j];
            y[i] = s;
        }
        return y;
    }

    public static double[] Subtract(double[] a, double[] b)
    {
        double[] c = new double[a.Length];
        for (int i = 0; i < a.Length; i++) c[i] = a[i] - b[i];
        return c;
    }

    public static double[,] Cholesky(double[,] A)
    {
        int n = A.GetLength(0);
        double[,] L = new double[n, n];
        for (int i = 0; i < n; i++)
        {
            for (int j = 0; j <= i; j++)
            {
                double sum = A[i, j];
                for (int k = 0; k < j; k++) sum -= L[i, k] * L[j, k];
                if (i == j)
                {
                    if (sum <= 0) throw new InvalidOperationException("not positive definite");
                    L[i, j] = Math.Sqrt(sum);
                }
                else
                {
                    L[i, j] = sum / L[j, j];
                }
            }
        }
        return L;
    }
}

#endregion

#region Statistics Correlation

public static class Statistics
{
    public static double Pearson(ReadOnlySpan<double> x, ReadOnlySpan<double> y)
    {
        if (x.Length != y.Length || x.Length < 2) return 0;
        double mx = NumericUtil.Mean(x);
        double my = NumericUtil.Mean(y);
        double num = 0, dx = 0, dy = 0;
        for (int i = 0; i < x.Length; i++)
        {
            double a = x[i] - mx;
            double b = y[i] - my;
            num += a * b;
            dx += a * a;
            dy += b * b;
        }
        double denom = Math.Sqrt(dx * dy);
        return denom == 0 ? 0 : num / denom;
    }

    public static double Spearman(ReadOnlySpan<double> x, ReadOnlySpan<double> y)
    {
        if (x.Length != y.Length) return 0;
        var rx = Rank(x);
        var ry = Rank(y);
        return Pearson(rx, ry);
    }

    private static double[] Rank(ReadOnlySpan<double> values)
    {
        int n = values.Length;
        var indices = Enumerable.Range(0, n).ToArray();
        Array.Sort(indices, (a, b) => values[a].CompareTo(values[b]));
        var ranks = new double[n];
        for (int i = 0; i < n; i++) ranks[indices[i]] = i + 1;
        return ranks;
    }

    public static (double slope, double intercept) LinearRegression(ReadOnlySpan<double> x, ReadOnlySpan<double> y)
    {
        if (x.Length != y.Length || x.Length < 2) return (0, 0);
        double mx = NumericUtil.Mean(x);
        double my = NumericUtil.Mean(y);
        double num = 0, den = 0;
        for (int i = 0; i < x.Length; i++)
        {
            num += (x[i] - mx) * (y[i] - my);
            den += (x[i] - mx) * (x[i] - mx);
        }
        if (den == 0) return (0, my);
        double slope = num / den;
        double intercept = my - slope * mx;
        return (slope, intercept);
    }
}

#endregion

#region Trie

public sealed class Trie<TValue>
{
    private sealed class Node
    {
        public Dictionary<char, Node>? Children;
        public TValue? Value;
        public bool HasValue;
    }

    private readonly Node _root = new();

    public void Insert(string key, TValue value)
    {
        var node = _root;
        foreach (char c in key)
        {
            node.Children ??= new Dictionary<char, Node>();
            if (!node.Children.TryGetValue(c, out var next))
            {
                next = new Node();
                node.Children[c] = next;
            }
            node = next;
        }
        node.Value = value;
        node.HasValue = true;
    }

    public bool TryGet(string key, out TValue? value)
    {
        var node = _root;
        foreach (char c in key)
        {
            if (node.Children == null || !node.Children.TryGetValue(c, out var next))
            {
                value = default;
                return false;
            }
            node = next;
        }
        value = node.Value;
        return node.HasValue;
    }

    public IEnumerable<string> StartsWith(string prefix)
    {
        var node = _root;
        foreach (char c in prefix)
        {
            if (node.Children == null || !node.Children.TryGetValue(c, out var next))
                yield break;
            node = next;
        }
        var stack = new Stack<(Node node, string path)>();
        stack.Push((node, prefix));
        while (stack.Count > 0)
        {
            var (current, path) = stack.Pop();
            if (current.HasValue) yield return path;
            if (current.Children != null)
            {
                foreach (var kv in current.Children)
                    stack.Push((kv.Value, path + kv.Key));
            }
        }
    }
}

#endregion

#region LRU Cache

public sealed class LruCache<TKey, TValue> where TKey : notnull
{
    private sealed class Entry
    {
        public TKey Key = default!;
        public TValue Value = default!;
        public LinkedListNode<TKey>? Node;
    }

    private readonly int _capacity;
    private readonly Dictionary<TKey, Entry> _map;
    private readonly LinkedList<TKey> _lru = new();
    private readonly object _lock = new();

    public LruCache(int capacity)
    {
        _capacity = capacity;
        _map = new Dictionary<TKey, Entry>(capacity);
    }

    public bool TryGet(TKey key, out TValue? value)
    {
        lock (_lock)
        {
            if (_map.TryGetValue(key, out var entry))
            {
                _lru.Remove(entry.Node!);
                _lru.AddFirst(entry.Node!);
                value = entry.Value;
                return true;
            }
            value = default;
            return false;
        }
    }

    public void Set(TKey key, TValue value)
    {
        lock (_lock)
        {
            if (_map.TryGetValue(key, out var existing))
            {
                existing.Value = value;
                _lru.Remove(existing.Node!);
                _lru.AddFirst(existing.Node!);
                return;
            }

            if (_map.Count >= _capacity)
            {
                var last = _lru.Last!;
                _lru.RemoveLast();
                _map.Remove(last.Value);
            }

            var node = _lru.AddFirst(key);
            _map[key] = new Entry { Key = key, Value = value, Node = node };
        }
    }

    public int Count { get { lock (_lock) return _map.Count; } }
}

#endregion

#region Priority Queue

public sealed class BinaryHeap<T>
{
    private readonly List<T> _items = new();
    private readonly Comparison<T> _comparison;

    public BinaryHeap(Comparison<T> comparison) => _comparison = comparison;

    public int Count => _items.Count;
    public bool IsEmpty => _items.Count == 0;

    public void Push(T item)
    {
        _items.Add(item);
        SiftUp(_items.Count - 1);
    }

    public T Pop()
    {
        if (_items.Count == 0) throw new InvalidOperationException("empty");
        T root = _items[0];
        int last = _items.Count - 1;
        _items[0] = _items[last];
        _items.RemoveAt(last);
        if (_items.Count > 0) SiftDown(0);
        return root;
    }

    public T Peek() => _items.Count == 0 ? throw new InvalidOperationException("empty") : _items[0];

    private void SiftUp(int i)
    {
        while (i > 0)
        {
            int parent = (i - 1) / 2;
            if (_comparison(_items[i], _items[parent]) >= 0) break;
            (_items[i], _items[parent]) = (_items[parent], _items[i]);
            i = parent;
        }
    }

    private void SiftDown(int i)
    {
        int n = _items.Count;
        while (true)
        {
            int left = 2 * i + 1;
            int right = 2 * i + 2;
            int smallest = i;
            if (left < n && _comparison(_items[left], _items[smallest]) < 0) smallest = left;
            if (right < n && _comparison(_items[right], _items[smallest]) < 0) smallest = right;
            if (smallest == i) break;
            (_items[i], _items[smallest]) = (_items[smallest], _items[i]);
            i = smallest;
        }
    }
}

#endregion

#region Union Find

public sealed class UnionFind
{
    private readonly int[] _parent;
    private readonly int[] _rank;
    private int _components;

    public UnionFind(int n)
    {
        _parent = new int[n];
        _rank = new int[n];
        _components = n;
        for (int i = 0; i < n; i++) _parent[i] = i;
    }

    public int Find(int x)
    {
        while (_parent[x] != x)
        {
            _parent[x] = _parent[_parent[x]];
            x = _parent[x];
        }
        return x;
    }

    public bool Union(int a, int b)
    {
        int ra = Find(a);
        int rb = Find(b);
        if (ra == rb) return false;
        if (_rank[ra] < _rank[rb]) (ra, rb) = (rb, ra);
        _parent[rb] = ra;
        if (_rank[ra] == _rank[rb]) _rank[ra]++;
        _components--;
        return true;
    }

    public int Components => _components;
}

#endregion

#region Segment Tree

public sealed class SegmentTree
{
    private readonly long[] _tree;
    private readonly int _n;

    public SegmentTree(ReadOnlySpan<long> data)
    {
        _n = 1;
        while (_n < data.Length) _n <<= 1;
        _tree = new long[2 * _n];
        for (int i = 0; i < data.Length; i++) _tree[_n + i] = data[i];
        for (int i = _n - 1; i >= 1; i--) _tree[i] = _tree[2 * i] + _tree[2 * i + 1];
    }

    public void Update(int index, long value)
    {
        int i = index + _n;
        _tree[i] = value;
        i >>= 1;
        while (i >= 1)
        {
            _tree[i] = _tree[2 * i] + _tree[2 * i + 1];
            i >>= 1;
        }
    }

    public long Query(int left, int right)
    {
        long result = 0;
        int l = left + _n;
        int r = right + _n + 1;
        while (l < r)
        {
            if ((l & 1) == 1) result += _tree[l++];
            if ((r & 1) == 1) result += _tree[--r];
            l >>= 1;
            r >>= 1;
        }
        return result;
    }
}

#endregion

#region Fenwick Tree

public sealed class FenwickTree
{
    private readonly long[] _tree;

    public FenwickTree(int n) => _tree = new long[n + 1];

    public void Add(int i, long delta)
    {
        i++;
        while (i < _tree.Length)
        {
            _tree[i] += delta;
            i += i & (-i);
        }
    }

    public long PrefixSum(int i)
    {
        long sum = 0;
        i++;
        while (i > 0)
        {
            sum += _tree[i];
            i -= i & (-i);
        }
        return sum;
    }

    public long RangeSum(int l, int r) => PrefixSum(r) - PrefixSum(l - 1);
}

#endregion

#region Sparse Table

public sealed class SparseTable
{
    private readonly int[,] _table;
    private readonly int[] _log;
    private readonly int _n;

    public SparseTable(ReadOnlySpan<int> data)
    {
        _n = data.Length;
        int k = 1;
        while ((1 << k) <= _n) k++;
        _table = new int[k, _n];
        _log = new int[_n + 1];

        for (int i = 2; i <= _n; i++) _log[i] = _log[i / 2] + 1;
        for (int i = 0; i < _n; i++) _table[0, i] = data[i];

        for (int j = 1; j < k; j++)
        {
            for (int i = 0; i + (1 << j) <= _n; i++)
            {
                _table[j, i] = Math.Min(_table[j - 1, i], _table[j - 1, i + (1 << (j - 1))]);
            }
        }
    }

    public int RangeMin(int l, int r)
    {
        int j = _log[r - l + 1];
        return Math.Min(_table[j, l], _table[j, r - (1 << j) + 1]);
    }
}

#endregion

#region Aho Corasick

public sealed class AhoCorasick
{
    private sealed class Node
    {
        public Dictionary<char, int> Transitions = new();
        public int Fail;
        public List<int> Outputs = new();
    }

    private readonly List<Node> _nodes = new() { new Node() };

    public void Add(string pattern, int id)
    {
        int current = 0;
        foreach (char c in pattern)
        {
            if (!_nodes[current].Transitions.TryGetValue(c, out int next))
            {
                next = _nodes.Count;
                _nodes.Add(new Node());
                _nodes[current].Transitions[c] = next;
            }
            current = next;
        }
        _nodes[current].Outputs.Add(id);
    }

    public void Build()
    {
        var queue = new Queue<int>();
        foreach (var kv in _nodes[0].Transitions)
        {
            int child = kv.Value;
            _nodes[child].Fail = 0;
            queue.Enqueue(child);
        }

        while (queue.Count > 0)
        {
            int current = queue.Dequeue();
            foreach (var kv in _nodes[current].Transitions)
            {
                char c = kv.Key;
                int child = kv.Value;
                int fail = _nodes[current].Fail;

                while (fail != 0 && !_nodes[fail].Transitions.ContainsKey(c))
                    fail = _nodes[fail].Fail;

                if (_nodes[fail].Transitions.TryGetValue(c, out int failChild) && failChild != child)
                {
                    _nodes[child].Fail = failChild;
                }
                else
                {
                    _nodes[child].Fail = 0;
                }

                _nodes[child].Outputs.AddRange(_nodes[_nodes[child].Fail].Outputs);
                queue.Enqueue(child);
            }
        }
    }

    public IEnumerable<(int endIndex, int patternId)> Search(string text)
    {
        int current = 0;
        for (int i = 0; i < text.Length; i++)
        {
            char c = text[i];
            while (current != 0 && !_nodes[current].Transitions.ContainsKey(c))
                current = _nodes[current].Fail;

            if (_nodes[current].Transitions.TryGetValue(c, out int next))
                current = next;

            foreach (int id in _nodes[current].Outputs)
                yield return (i, id);
        }
    }
}

#endregion

#region Suffix Array

public static class SuffixArray
{
    public static int[] Build(string text)
    {
        int n = text.Length;
        int[] sa = new int[n];
        int[] rank = new int[n];
        int[] tmp = new int[n];

        for (int i = 0; i < n; i++) { sa[i] = i; rank[i] = text[i]; }

        for (int k = 1; k < n; k <<= 1)
        {
            int kCopy = k;
            Comparison<int> cmp = (a, b) =>
            {
                if (rank[a] != rank[b]) return rank[a].CompareTo(rank[b]);
                int ra = a + kCopy < n ? rank[a + kCopy] : -1;
                int rb = b + kCopy < n ? rank[b + kCopy] : -1;
                return ra.CompareTo(rb);
            };
            Array.Sort(sa, cmp);
            tmp[sa[0]] = 0;
            for (int i = 1; i < n; i++)
                tmp[sa[i]] = tmp[sa[i - 1]] + (cmp(sa[i - 1], sa[i]) < 0 ? 1 : 0);
            Array.Copy(tmp, rank, n);
            if (rank[sa[n - 1]] == n - 1) break;
        }
        return sa;
    }

    public static int[] BuildLcp(string text, int[] sa)
    {
        int n = text.Length;
        int[] rank = new int[n];
        for (int i = 0; i < n; i++) rank[sa[i]] = i;

        int[] lcp = new int[n];
        int h = 0;
        for (int i = 0; i < n; i++)
        {
            if (rank[i] > 0)
            {
                int j = sa[rank[i] - 1];
                while (i + h < n && j + h < n && text[i + h] == text[j + h]) h++;
                lcp[rank[i]] = h;
                if (h > 0) h--;
            }
        }
        return lcp;
    }
}

#endregion

#region Z Algorithm

public static class ZAlgorithm
{
    public static int[] Compute(ReadOnlySpan<char> s)
    {
        int n = s.Length;
        int[] z = new int[n];
        int l = 0, r = 0;
        for (int i = 1; i < n; i++)
        {
            if (i <= r) z[i] = Math.Min(r - i + 1, z[i - l]);
            while (i + z[i] < n && s[z[i]] == s[i + z[i]]) z[i]++;
            if (i + z[i] - 1 > r)
            {
                l = i;
                r = i + z[i] - 1;
            }
        }
        return z;
    }
}

#endregion

#region KMP

public static class Kmp
{
    public static int[] BuildFailure(string pattern)
    {
        int n = pattern.Length;
        int[] fail = new int[n];
        int k = 0;
        for (int i = 1; i < n; i++)
        {
            while (k > 0 && pattern[k] != pattern[i]) k = fail[k - 1];
            if (pattern[k] == pattern[i]) k++;
            fail[i] = k;
        }
        return fail;
    }

    public static IEnumerable<int> Search(string text, string pattern)
    {
        int[] fail = BuildFailure(pattern);
        int k = 0;
        for (int i = 0; i < text.Length; i++)
        {
            while (k > 0 && text[i] != pattern[k]) k = fail[k - 1];
            if (text[i] == pattern[k]) k++;
            if (k == pattern.Length)
            {
                yield return i - pattern.Length + 1;
                k = fail[k - 1];
            }
        }
    }
}

#endregion

#region Manacher

public static class Manacher
{
    public static string LongestPalindrome(string s)
    {
        if (string.IsNullOrEmpty(s)) return "";
        string t = "^#" + string.Join("#", s.ToCharArray()) + "#$";
        int n = t.Length;
        int[] p = new int[n];
        int center = 0, right = 0;
        for (int i = 1; i < n - 1; i++)
        {
            int mirror = 2 * center - i;
            if (i < right) p[i] = Math.Min(right - i, p[mirror]);
            while (t[i + p[i] + 1] == t[i - p[i] - 1]) p[i]++;
            if (i + p[i] > right)
            {
                center = i;
                right = i + p[i];
            }
        }
        int maxLen = 0, maxCenter = 0;
        for (int i = 1; i < n - 1; i++)
        {
            if (p[i] > maxLen)
            {
                maxLen = p[i];
                maxCenter = i;
            }
        }
        int start = (maxCenter - maxLen) / 2;
        return s.Substring(start, maxLen);
    }
}

#endregion

#region Huffman

public sealed class HuffmanCodec
{
    public sealed class Node
    {
        public char? Symbol;
        public int Frequency;
        public Node? Left;
        public Node? Right;
    }

    public static Dictionary<char, string> BuildCodes(string text)
    {
        var freq = new Dictionary<char, int>();
        foreach (char c in text)
        {
            freq.TryGetValue(c, out int existing);
            freq[c] = existing + 1;
        }

        var heap = new BinaryHeap<Node>((a, b) => a.Frequency.CompareTo(b.Frequency));
        foreach (var kv in freq)
            heap.Push(new Node { Symbol = kv.Key, Frequency = kv.Value });

        while (heap.Count > 1)
        {
            var a = heap.Pop();
            var b = heap.Pop();
            heap.Push(new Node
            {
                Frequency = a.Frequency + b.Frequency,
                Left = a,
                Right = b
            });
        }

        var root = heap.Pop();
        var codes = new Dictionary<char, string>();
        BuildCodesRecursive(root, "", codes);
        return codes;
    }

    private static void BuildCodesRecursive(Node node, string prefix, Dictionary<char, string> codes)
    {
        if (node.Symbol.HasValue)
        {
            codes[node.Symbol.Value] = prefix.Length == 0 ? "0" : prefix;
            return;
        }
        if (node.Left != null) BuildCodesRecursive(node.Left, prefix + "0", codes);
        if (node.Right != null) BuildCodesRecursive(node.Right, prefix + "1", codes);
    }
}

#endregion

#region Fast Fourier Transform

public static class Fft
{
    public static Complex[] Forward(Complex[] input)
    {
        int n = input.Length;
        if (n == 1) return new[] { input[0] };
        if ((n & (n - 1)) != 0) throw new ArgumentException("length must be power of two");

        var even = new Complex[n / 2];
        var odd = new Complex[n / 2];
        for (int i = 0; i < n / 2; i++)
        {
            even[i] = input[2 * i];
            odd[i] = input[2 * i + 1];
        }

        var evenFft = Forward(even);
        var oddFft = Forward(odd);
        var result = new Complex[n];
        for (int k = 0; k < n / 2; k++)
        {
            var t = Complex.FromPolarCoordinates(1, -2 * Math.PI * k / n) * oddFft[k];
            result[k] = evenFft[k] + t;
            result[k + n / 2] = evenFft[k] - t;
        }
        return result;
    }

    public static Complex[] Inverse(Complex[] input)
    {
        int n = input.Length;
        var conjugate = new Complex[n];
        for (int i = 0; i < n; i++) conjugate[i] = Complex.Conjugate(input[i]);
        var fft = Forward(conjugate);
        var result = new Complex[n];
        for (int i = 0; i < n; i++) result[i] = Complex.Conjugate(fft[i]) / n;
        return result;
    }

    public static double[] Convolve(double[] a, double[] b)
    {
        int n = 1;
        while (n < a.Length + b.Length - 1) n <<= 1;
        var fa = new Complex[n];
        var fb = new Complex[n];
        for (int i = 0; i < a.Length; i++) fa[i] = new Complex(a[i], 0);
        for (int i = 0; i < b.Length; i++) fb[i] = new Complex(b[i], 0);
        var ffa = Forward(fa);
        var ffb = Forward(fb);
        var fc = new Complex[n];
        for (int i = 0; i < n; i++) fc[i] = ffa[i] * ffb[i];
        var c = Inverse(fc);
        var result = new double[a.Length + b.Length - 1];
        for (int i = 0; i < result.Length; i++) result[i] = c[i].Real;
        return result;
    }
}

#endregion

#region Monotonic Stack

public static class MonotonicStack
{
    public static int[] NextGreaterElement(ReadOnlySpan<int> data)
    {
        int n = data.Length;
        int[] result = new int[n];
        Array.Fill(result, -1);
        var stack = new Stack<int>();
        for (int i = 0; i < n; i++)
        {
            while (stack.Count > 0 && data[stack.Peek()] < data[i])
                result[stack.Pop()] = i;
            stack.Push(i);
        }
        return result;
    }

    public static int[] PreviousSmallerElement(ReadOnlySpan<int> data)
    {
        int n = data.Length;
        int[] result = new int[n];
        Array.Fill(result, -1);
        var stack = new Stack<int>();
        for (int i = 0; i < n; i++)
        {
            while (stack.Count > 0 && data[stack.Peek()] >= data[i])
                stack.Pop();
            if (stack.Count > 0) result[i] = stack.Peek();
            stack.Push(i);
        }
        return result;
    }

    public static long LargestRectangleInHistogram(ReadOnlySpan<int> heights)
    {
        int n = heights.Length;
        var stack = new Stack<int>();
        long max = 0;
        for (int i = 0; i <= n; i++)
        {
            int h = i == n ? 0 : heights[i];
            while (stack.Count > 0 && heights[stack.Peek()] >= h)
            {
                int height = heights[stack.Pop()];
                int width = stack.Count == 0 ? i : i - stack.Peek() - 1;
                max = Math.Max(max, (long)height * width);
            }
            stack.Push(i);
        }
        return max;
    }
}

#endregion

#region Binary Search Tree

public sealed class Bst<TKey, TValue> where TKey : IComparable<TKey>
{
    private sealed class Node
    {
        public TKey Key = default!;
        public TValue Value = default!;
        public Node? Left, Right;
    }

    private Node? _root;
    private int _count;

    public int Count => _count;
    public bool IsEmpty => _root == null;

    public bool TryGet(TKey key, out TValue? value)
    {
        var current = _root;
        while (current != null)
        {
            int cmp = key.CompareTo(current.Key);
            if (cmp == 0) { value = current.Value; return true; }
            current = cmp < 0 ? current.Left : current.Right;
        }
        value = default;
        return false;
    }

    public void Insert(TKey key, TValue value)
    {
        ref Node? slot = ref _root;
        while (true)
        {
            if (slot == null)
            {
                slot = new Node { Key = key, Value = value };
                _count++;
                return;
            }
            int cmp = key.CompareTo(slot.Key);
            if (cmp == 0) { slot.Value = value; return; }
            slot = ref (cmp < 0 ? ref slot.Left : ref slot.Right);
        }
    }

    public IEnumerable<(TKey key, TValue value)> InOrder()
    {
        var stack = new Stack<Node>();
        var current = _root;
        while (current != null || stack.Count > 0)
        {
            while (current != null)
            {
                stack.Push(current);
                current = current.Left;
            }
            current = stack.Pop();
            yield return (current.Key, current.Value);
            current = current.Right;
        }
    }
}

#endregion

#region Skip List

public sealed class SkipList<TKey> where TKey : IComparable<TKey>
{
    private sealed class Node
    {
        public TKey? Key;
        public Node[] Forward = Array.Empty<Node>();
    }

    private const int MaxLevel = 24;
    private readonly Node _head = new();
    private readonly Random _random = new(42);
    private int _level;

    public SkipList()
    {
        _head.Forward = new Node[MaxLevel];
    }

    public void Insert(TKey key)
    {
        var update = new Node[MaxLevel];
        var current = _head;
        for (int i = _level - 1; i >= 0; i--)
        {
            while (current.Forward[i] != null && current.Forward[i].Key!.CompareTo(key) < 0)
                current = current.Forward[i];
            update[i] = current;
        }

        int newLevel = 1;
        while (newLevel < MaxLevel && _random.Next(2) == 1) newLevel++;

        if (newLevel > _level)
        {
            for (int i = _level; i < newLevel; i++) update[i] = _head;
            _level = newLevel;
        }

        var node = new Node { Key = key, Forward = new Node[newLevel] };
        for (int i = 0; i < newLevel; i++)
        {
            node.Forward[i] = update[i].Forward[i];
            update[i].Forward[i] = node;
        }
    }

    public bool Contains(TKey key)
    {
        var current = _head;
        for (int i = _level - 1; i >= 0; i--)
        {
            while (current.Forward[i] != null && current.Forward[i].Key!.CompareTo(key) < 0)
                current = current.Forward[i];
        }
        current = current.Forward[0];
        return current != null && current.Key!.CompareTo(key) == 0;
    }
}

#endregion

#region Treap

public sealed class Treap<TKey> where TKey : IComparable<TKey>
{
    private sealed class Node
    {
        public TKey Key = default!;
        public int Priority;
        public Node? Left, Right;
    }

    private readonly Random _rng = new(42);
    private Node? _root;

    public void Insert(TKey key) => _root = InsertRecursive(_root, key);

    private Node InsertRecursive(Node? node, TKey key)
    {
        if (node == null) return new Node { Key = key, Priority = _rng.Next() };
        int cmp = key.CompareTo(node.Key);
        if (cmp < 0)
        {
            node.Left = InsertRecursive(node.Left, key);
            if (node.Left.Priority < node.Priority) node = RotateRight(node);
        }
        else if (cmp > 0)
        {
            node.Right = InsertRecursive(node.Right, key);
            if (node.Right.Priority < node.Priority) node = RotateLeft(node);
        }
        return node;
    }

    private static Node RotateRight(Node y)
    {
        var x = y.Left!;
        y.Left = x.Right;
        x.Right = y;
        return x;
    }

    private static Node RotateLeft(Node x)
    {
        var y = x.Right!;
        x.Right = y.Left;
        y.Left = x;
        return y;
    }

    public bool Contains(TKey key)
    {
        var current = _root;
        while (current != null)
        {
            int cmp = key.CompareTo(current.Key);
            if (cmp == 0) return true;
            current = cmp < 0 ? current.Left : current.Right;
        }
        return false;
    }
}

#endregion

#region Spectral Analysis

public static class Spectral
{
    public static double[] Autocorrelation(ReadOnlySpan<double> signal, int maxLag)
    {
        int n = signal.Length;
        double mean = NumericUtil.Mean(signal);
        double[] acf = new double[maxLag];
        double denom = 0;
        for (int i = 0; i < n; i++) denom += (signal[i] - mean) * (signal[i] - mean);

        for (int lag = 0; lag < maxLag; lag++)
        {
            double num = 0;
            for (int i = 0; i < n - lag; i++)
                num += (signal[i] - mean) * (signal[i + lag] - mean);
            acf[lag] = denom == 0 ? 0 : num / denom;
        }
        return acf;
    }

    public static double[] HammingWindow(int n)
    {
        double[] w = new double[n];
        for (int i = 0; i < n; i++)
            w[i] = 0.54 - 0.46 * Math.Cos(2 * Math.PI * i / (n - 1));
        return w;
    }

    public static double[] HannWindow(int n)
    {
        double[] w = new double[n];
        for (int i = 0; i < n; i++)
            w[i] = 0.5 * (1 - Math.Cos(2 * Math.PI * i / (n - 1)));
        return w;
    }

    public static double[] BlackmanWindow(int n)
    {
        double[] w = new double[n];
        for (int i = 0; i < n; i++)
        {
            double t = 2 * Math.PI * i / (n - 1);
            w[i] = 0.42 - 0.5 * Math.Cos(t) + 0.08 * Math.Cos(2 * t);
        }
        return w;
    }
}

#endregion

#region String Distance

public static class StringDistance
{
    public static int Levenshtein(ReadOnlySpan<char> a, ReadOnlySpan<char> b)
    {
        int n = a.Length, m = b.Length;
        if (n == 0) return m;
        if (m == 0) return n;

        Span<int> prev = stackalloc int[m + 1];
        Span<int> curr = stackalloc int[m + 1];

        for (int j = 0; j <= m; j++) prev[j] = j;

        for (int i = 1; i <= n; i++)
        {
            curr[0] = i;
            for (int j = 1; j <= m; j++)
            {
                int cost = a[i - 1] == b[j - 1] ? 0 : 1;
                curr[j] = Math.Min(Math.Min(curr[j - 1] + 1, prev[j] + 1), prev[j - 1] + cost);
            }
            prev.Slice(0, m + 1).CopyTo(curr);
            (prev, curr) = (curr, prev);
        }
        return prev[m];
    }

    public static int DamerauLevenshtein(ReadOnlySpan<char> a, ReadOnlySpan<char> b)
    {
        int n = a.Length, m = b.Length;
        int[,] d = new int[n + 1, m + 1];
        for (int i = 0; i <= n; i++) d[i, 0] = i;
        for (int j = 0; j <= m; j++) d[0, j] = j;

        for (int i = 1; i <= n; i++)
        {
            for (int j = 1; j <= m; j++)
            {
                int cost = a[i - 1] == b[j - 1] ? 0 : 1;
                d[i, j] = Math.Min(Math.Min(d[i - 1, j] + 1, d[i, j - 1] + 1), d[i - 1, j - 1] + cost);
                if (i > 1 && j > 1 && a[i - 1] == b[j - 2] && a[i - 2] == b[j - 1])
                    d[i, j] = Math.Min(d[i, j], d[i - 2, j - 2] + 1);
            }
        }
        return d[n, m];
    }

    public static int Hamming(ReadOnlySpan<char> a, ReadOnlySpan<char> b)
    {
        if (a.Length != b.Length) throw new ArgumentException("lengths must match");
        int dist = 0;
        for (int i = 0; i < a.Length; i++)
            if (a[i] != b[i]) dist++;
        return dist;
    }

    public static int JaroWinkler(ReadOnlySpan<char> a, ReadOnlySpan<char> b)
    {
        return (int)(JaroWinklerSimilarity(a, b) * 100);
    }

    public static double JaroWinklerSimilarity(ReadOnlySpan<char> a, ReadOnlySpan<char> b)
    {
        if (a.Length == 0 && b.Length == 0) return 1.0;
        if (a.Length == 0 || b.Length == 0) return 0.0;

        int matchDistance = Math.Max(a.Length, b.Length) / 2 - 1;
        bool[] aMatches = new bool[a.Length];
        bool[] bMatches = new bool[b.Length];
        int matches = 0;

        for (int i = 0; i < a.Length; i++)
        {
            int start = Math.Max(0, i - matchDistance);
            int end = Math.Min(i + matchDistance + 1, b.Length);
            for (int j = start; j < end; j++)
            {
                if (bMatches[j] || a[i] != b[j]) continue;
                aMatches[i] = true;
                bMatches[j] = true;
                matches++;
                break;
            }
        }

        if (matches == 0) return 0.0;

        int transpositions = 0;
        int k = 0;
        for (int i = 0; i < a.Length; i++)
        {
            if (!aMatches[i]) continue;
            while (!bMatches[k]) k++;
            if (a[i] != b[k]) transpositions++;
            k++;
        }
        transpositions /= 2;

        double jaro = (matches / (double)a.Length + matches / (double)b.Length
            + (matches - transpositions) / (double)matches) / 3.0;

        int prefix = 0;
        for (int i = 0; i < Math.Min(4, Math.Min(a.Length, b.Length)); i++)
        {
            if (a[i] == b[i]) prefix++;
            else break;
        }

        return jaro + prefix * 0.1 * (1 - jaro);
    }
}

#endregion

#region Token Bucket Rate Limiter

public sealed class TokenBucket
{
    private readonly double _capacity;
    private readonly double _refillRate;
    private readonly object _lock = new();
    private double _tokens;
    private long _lastRefillTicks;

    public TokenBucket(double capacity, double refillPerSecond)
    {
        _capacity = capacity;
        _refillRate = refillPerSecond;
        _tokens = capacity;
        _lastRefillTicks = Stopwatch.GetTimestamp();
    }

    public bool TryConsume(double amount = 1.0)
    {
        lock (_lock)
        {
            Refill();
            if (_tokens >= amount)
            {
                _tokens -= amount;
                return true;
            }
            return false;
        }
    }

    private void Refill()
    {
        long now = Stopwatch.GetTimestamp();
        double elapsed = (now - _lastRefillTicks) / (double)Stopwatch.Frequency;
        _lastRefillTicks = now;
        _tokens = Math.Min(_capacity, _tokens + elapsed * _refillRate);
    }

    public double Available { get { lock (_lock) { Refill(); return _tokens; } } }
}

#endregion

#region Sliding Window

public sealed class SlidingWindowCounter
{
    private readonly int _windowSizeMs;
    private readonly Queue<long> _timestamps = new();
    private readonly object _lock = new();

    public SlidingWindowCounter(int windowSizeMs) => _windowSizeMs = windowSizeMs;

    public void Record()
    {
        lock (_lock)
        {
            long now = Stopwatch.GetTimestamp() / (Stopwatch.Frequency / 1000);
            _timestamps.Enqueue(now);
            Trim(now);
        }
    }

    public int Count
    {
        get
        {
            lock (_lock)
            {
                long now = Stopwatch.GetTimestamp() / (Stopwatch.Frequency / 1000);
                Trim(now);
                return _timestamps.Count;
            }
        }
    }

    private void Trim(long now)
    {
        long threshold = now - _windowSizeMs;
        while (_timestamps.Count > 0 && _timestamps.Peek() < threshold)
            _timestamps.Dequeue();
    }
}

#endregion

#region Entropy Pool

public sealed class EntropyPool
{
    private readonly byte[] _pool;
    private int _position;
    private readonly object _lock = new();

    public EntropyPool(int size = 1024)
    {
        _pool = new byte[size];
        using var rng = RandomNumberGenerator.Create();
        rng.GetBytes(_pool);
        _position = 0;
    }

    public void Mix(ReadOnlySpan<byte> data)
    {
        lock (_lock)
        {
            foreach (byte b in data)
            {
                _pool[_position] ^= b;
                _pool[_position] = (byte)BitMath.Murmur(_pool[_position]);
                _position = (_position + 1) % _pool.Length;
            }
        }
    }

    public byte[] Extract(int length)
    {
        lock (_lock)
        {
            byte[] result = new byte[length];
            for (int i = 0; i < length; i++)
            {
                int idx = (_position + i) % _pool.Length;
                result[i] = (byte)BitMath.Murmur(_pool[idx] ^ (byte)i);
            }
            return result;
        }
    }
}

#endregion

#region Fixed Point Arithmetic

public readonly struct Fixed32 : IComparable<Fixed32>, IEquatable<Fixed32>
{
    private const int FractionBits = 16;
    private const int One = 1 << FractionBits;
    private const long Mask = (1L << FractionBits) - 1;

    public readonly int Raw;

    public Fixed32(int raw) => Raw = raw;

    public static Fixed32 FromDouble(double value) => new((int)(value * One));
    public static Fixed32 FromInt(int value) => new(value << FractionBits);

    public double ToDouble() => Raw / (double)One;
    public int ToInt() => Raw >> FractionBits;

    public static Fixed32 operator +(Fixed32 a, Fixed32 b) => new(a.Raw + b.Raw);
    public static Fixed32 operator -(Fixed32 a, Fixed32 b) => new(a.Raw - b.Raw);
    public static Fixed32 operator *(Fixed32 a, Fixed32 b) => new((int)(((long)a.Raw * b.Raw) >> FractionBits));
    public static Fixed32 operator /(Fixed32 a, Fixed32 b) => new((int)(((long)a.Raw << FractionBits) / b.Raw));

    public static bool operator <(Fixed32 a, Fixed32 b) => a.Raw < b.Raw;
    public static bool operator >(Fixed32 a, Fixed32 b) => a.Raw > b.Raw;
    public static bool operator <=(Fixed32 a, Fixed32 b) => a.Raw <= b.Raw;
    public static bool operator >=(Fixed32 a, Fixed32 b) => a.Raw >= b.Raw;
    public static bool operator ==(Fixed32 a, Fixed32 b) => a.Raw == b.Raw;
    public static bool operator !=(Fixed32 a, Fixed32 b) => a.Raw != b.Raw;

    public int CompareTo(Fixed32 other) => Raw.CompareTo(other.Raw);
    public bool Equals(Fixed32 other) => Raw == other.Raw;
    public override bool Equals(object? obj) => obj is Fixed32 f && Equals(f);
    public override int GetHashCode() => Raw;
    public override string ToString() => ToDouble().ToString(CultureInfo.InvariantCulture);
}

#endregion

#region Rational Numbers

public readonly struct Rational : IComparable<Rational>, IEquatable<Rational>
{
    public readonly long Numerator;
    public readonly long Denominator;

    public Rational(long numerator, long denominator = 1)
    {
        if (denominator == 0) throw new DivideByZeroException();
        if (denominator < 0) { numerator = -numerator; denominator = -denominator; }
        long g = Gcd(Math.Abs(numerator), denominator);
        Numerator = numerator / g;
        Denominator = denominator / g;
    }

    private static long Gcd(long a, long b)
    {
        while (b != 0) (a, b) = (b, a % b);
        return a;
    }

    public static Rational operator +(Rational a, Rational b)
        => new(a.Numerator * b.Denominator + b.Numerator * a.Denominator, a.Denominator * b.Denominator);

    public static Rational operator -(Rational a, Rational b)
        => new(a.Numerator * b.Denominator - b.Numerator * a.Denominator, a.Denominator * b.Denominator);

    public static Rational operator *(Rational a, Rational b)
        => new(a.Numerator * b.Numerator, a.Denominator * b.Denominator);

    public static Rational operator /(Rational a, Rational b)
        => new(a.Numerator * b.Denominator, a.Denominator * b.Numerator);

    public int CompareTo(Rational other)
        => (Numerator * other.Denominator).CompareTo(other.Numerator * Denominator);

    public bool Equals(Rational other) => Numerator == other.Numerator && Denominator == other.Denominator;
    public override bool Equals(object? obj) => obj is Rational r && Equals(r);
    public override int GetHashCode() => HashCode.Combine(Numerator, Denominator);
    public override string ToString() => Denominator == 1 ? Numerator.ToString() : $"{Numerator}/{Denominator}";

    public double ToDouble() => (double)Numerator / Denominator;
}

#endregion

#region Complex Extensions

public static class ComplexExtensions
{
    public static Complex Cexp(this Complex z) => Complex.Exp(z);
    public static Complex Clog(this Complex z) => Complex.Log(z);
    public static Complex Csqrt(this Complex z) => Complex.Sqrt(z);
    public static Complex Cpow(this Complex z, Complex w) => Complex.Pow(z, w);

    public static Complex Csin(this Complex z)
        => new(Math.Sin(z.Real) * Math.Cosh(z.Imaginary), Math.Cos(z.Real) * Math.Sinh(z.Imaginary));

    public static Complex Ccos(this Complex z)
        => new(Math.Cos(z.Real) * Math.Cosh(z.Imaginary), -Math.Sin(z.Real) * Math.Sinh(z.Imaginary));

    public static double AbsSquared(this Complex z) => z.Real * z.Real + z.Imaginary * z.Imaginary;
}

#endregion

#region Permutation Generator

public static class Permutations
{
    public static IEnumerable<T[]> All<T>(T[] array)
    {
        int n = array.Length;
        int[] indices = Enumerable.Range(0, n).ToArray();
        yield return indices.Select(i => array[i]).ToArray();

        while (true)
        {
            int i = n - 2;
            while (i >= 0 && indices[i] >= indices[i + 1]) i--;
            if (i < 0) yield break;

            int j = n - 1;
            while (indices[j] <= indices[i]) j--;
            (indices[i], indices[j]) = (indices[j], indices[i]);

            Array.Reverse(indices, i + 1, n - i - 1);
            yield return indices.Select(k => array[k]).ToArray();
        }
    }

    public static long Count(int n)
    {
        long result = 1;
        for (int i = 2; i <= n; i++) result *= i;
        return result;
    }
}

#endregion

#region Combinations

public static class Combinations
{
    public static IEnumerable<T[]> Choose<T>(T[] array, int k)
    {
        int n = array.Length;
        if (k > n) yield break;
        int[] indices = Enumerable.Range(0, k).ToArray();
        yield return indices.Select(i => array[i]).ToArray();

        while (true)
        {
            int i = k - 1;
            while (i >= 0 && indices[i] == i + n - k) i--;
            if (i < 0) yield break;
            indices[i]++;
            for (int j = i + 1; j < k; j++) indices[j] = indices[j - 1] + 1;
            yield return indices.Select(idx => array[idx]).ToArray();
        }
    }

    public static long Count(int n, int k)
    {
        if (k < 0 || k > n) return 0;
        if (k > n - k) k = n - k;
        long result = 1;
        for (int i = 0; i < k; i++)
            result = result * (n - i) / (i + 1);
        return result;
    }
}

#endregion

#region Power Set

public static class PowerSet
{
    public static IEnumerable<IEnumerable<T>> All<T>(IReadOnlyList<T> source)
    {
        int n = source.Count;
        int total = 1 << n;
        for (int mask = 0; mask < total; mask++)
        {
            var subset = new List<T>();
            for (int i = 0; i < n; i++)
            {
                if ((mask & (1 << i)) != 0) subset.Add(source[i]);
            }
            yield return subset;
        }
    }
}

#endregion

#region Graph Algorithms

public sealed class Graph
{
    private readonly int _vertices;
    private readonly List<(int to, int weight)>[] _adjacency;

    public Graph(int vertices)
    {
        _vertices = vertices;
        _adjacency = new List<(int, int)>[vertices];
        for (int i = 0; i < vertices; i++) _adjacency[i] = new List<(int, int)>();
    }

    public void AddEdge(int from, int to, int weight = 1)
    {
        _adjacency[from].Add((to, weight));
    }

    public long[] Dijkstra(int source)
    {
        long[] dist = new long[_vertices];
        Array.Fill(dist, long.MaxValue);
        dist[source] = 0;

        var heap = new BinaryHeap<(int node, long distance)>((a, b) => a.distance.CompareTo(b.distance));
        heap.Push((source, 0));

        while (!heap.IsEmpty)
        {
            var (node, d) = heap.Pop();
            if (d > dist[node]) continue;

            foreach (var (to, weight) in _adjacency[node])
            {
                long newDist = dist[node] + weight;
                if (newDist < dist[to])
                {
                    dist[to] = newDist;
                    heap.Push((to, newDist));
                }
            }
        }
        return dist;
    }

    public (long[] dist, int[] parent) BellmanFord(int source)
    {
        long[] dist = new long[_vertices];
        int[] parent = new int[_vertices];
        Array.Fill(dist, long.MaxValue);
        Array.Fill(parent, -1);
        dist[source] = 0;

        for (int iter = 0; iter < _vertices - 1; iter++)
        {
            for (int u = 0; u < _vertices; u++)
            {
                if (dist[u] == long.MaxValue) continue;
                foreach (var (v, w) in _adjacency[u])
                {
                    if (dist[u] + w < dist[v])
                    {
                        dist[v] = dist[u] + w;
                        parent[v] = u;
                    }
                }
            }
        }

        for (int u = 0; u < _vertices; u++)
        {
            if (dist[u] == long.MaxValue) continue;
            foreach (var (v, w) in _adjacency[u])
            {
                if (dist[u] + w < dist[v])
                    throw new InvalidOperationException("negative cycle detected");
            }
        }
        return (dist, parent);
    }

    public int[] TopologicalSort()
    {
        int[] inDegree = new int[_vertices];
        for (int u = 0; u < _vertices; u++)
            foreach (var (v, _) in _adjacency[u]) inDegree[v]++;

        var queue = new Queue<int>();
        for (int i = 0; i < _vertices; i++)
            if (inDegree[i] == 0) queue.Enqueue(i);

        var order = new List<int>();
        while (queue.Count > 0)
        {
            int u = queue.Dequeue();
            order.Add(u);
            foreach (var (v, _) in _adjacency[u])
            {
                if (--inDegree[v] == 0) queue.Enqueue(v);
            }
        }

        if (order.Count != _vertices) throw new InvalidOperationException("cycle detected");
        return order.ToArray();
    }

    public List<List<int>> StronglyConnected()
    {
        var index = new int[_vertices];
        var lowlink = new int[_vertices];
        var onStack = new bool[_vertices];
        var stack = new Stack<int>();
        var result = new List<List<int>>();
        int currentIndex = 0;

        void StrongConnect(int v)
        {
            index[v] = currentIndex;
            lowlink[v] = currentIndex;
            currentIndex++;
            stack.Push(v);
            onStack[v] = true;

            foreach (var (w, _) in _adjacency[v])
            {
                if (index[w] == 0)
                {
                    StrongConnect(w);
                    lowlink[v] = Math.Min(lowlink[v], lowlink[w]);
                }
                else if (onStack[w])
                {
                    lowlink[v] = Math.Min(lowlink[v], index[w]);
                }
            }

            if (lowlink[v] == index[v])
            {
                var component = new List<int>();
                int w;
                do
                {
                    w = stack.Pop();
                    onStack[w] = false;
                    component.Add(w);
                } while (w != v);
                result.Add(component);
            }
        }

        for (int i = 0; i < _vertices; i++)
        {
            if (index[i] == 0) StrongConnect(i);
        }
        return result;
    }
}

#endregion

#region Floyd Warshall

public static class FloydWarshall
{
    public static long[,] Compute(int[,] adjacency)
    {
        int n = adjacency.GetLength(0);
        long[,] dist = new long[n, n];

        for (int i = 0; i < n; i++)
            for (int j = 0; j < n; j++)
                dist[i, j] = i == j ? 0 : (adjacency[i, j] > 0 ? adjacency[i, j] : long.MaxValue / 2);

        for (int k = 0; k < n; k++)
            for (int i = 0; i < n; i++)
                for (int j = 0; j < n; j++)
                    if (dist[i, k] + dist[k, j] < dist[i, j])
                        dist[i, j] = dist[i, k] + dist[k, j];

        return dist;
    }
}

#endregion

#region Knapsack

public static class Knapsack
{
    public static int Solve01(int[] weights, int[] values, int capacity)
    {
        int n = weights.Length;
        int[,] dp = new int[n + 1, capacity + 1];
        for (int i = 1; i <= n; i++)
        {
            for (int w = 0; w <= capacity; w++)
            {
                dp[i, w] = dp[i - 1, w];
                if (weights[i - 1] <= w)
                {
                    int withItem = dp[i - 1, w - weights[i - 1]] + values[i - 1];
                    if (withItem > dp[i, w]) dp[i, w] = withItem;
                }
            }
        }
        return dp[n, capacity];
    }

    public static int Solve01Optimized(int[] weights, int[] values, int capacity)
    {
        int[] dp = new int[capacity + 1];
        for (int i = 0; i < weights.Length; i++)
        {
            for (int w = capacity; w >= weights[i]; w--)
            {
                int withItem = dp[w - weights[i]] + values[i];
                if (withItem > dp[w]) dp[w] = withItem;
            }
        }
        return dp[capacity];
    }

    public static int SolveUnbounded(int[] weights, int[] values, int capacity)
    {
        int[] dp = new int[capacity + 1];
        for (int w = 1; w <= capacity; w++)
        {
            foreach (var _ in weights)
            {
                for (int i = 0; i < weights.Length; i++)
                {
                    if (weights[i] <= w)
                    {
                        int candidate = dp[w - weights[i]] + values[i];
                        if (candidate > dp[w]) dp[w] = candidate;
                    }
                }
            }
        }
        return dp[capacity];
    }
}

#endregion

#region Longest Common Subsequence

public static class Lcs
{
    public static int Length(ReadOnlySpan<char> a, ReadOnlySpan<char> b)
    {
        int n = a.Length, m = b.Length;
        int[,] dp = new int[n + 1, m + 1];
        for (int i = 1; i <= n; i++)
        {
            for (int j = 1; j <= m; j++)
            {
                if (a[i - 1] == b[j - 1])
                    dp[i, j] = dp[i - 1, j - 1] + 1;
                else
                    dp[i, j] = Math.Max(dp[i - 1, j], dp[i, j - 1]);
            }
        }
        return dp[n, m];
    }

    public static string Recover(ReadOnlySpan<char> a, ReadOnlySpan<char> b)
    {
        int n = a.Length, m = b.Length;
        int[,] dp = new int[n + 1, m + 1];
        for (int i = 1; i <= n; i++)
        {
            for (int j = 1; j <= m; j++)
            {
                if (a[i - 1] == b[j - 1])
                    dp[i, j] = dp[i - 1, j - 1] + 1;
                else
                    dp[i, j] = Math.Max(dp[i - 1, j], dp[i, j - 1]);
            }
        }

        var sb = new StringBuilder();
        int x = n, y = m;
        while (x > 0 && y > 0)
        {
            if (a[x - 1] == b[y - 1])
            {
                sb.Insert(0, a[x - 1]);
                x--;
                y--;
            }
            else if (dp[x - 1, y] >= dp[x, y - 1])
            {
                x--;
            }
            else
            {
                y--;
            }
        }
        return sb.ToString();
    }
}

#endregion

#region Edit Distance with Custom Costs

public static class EditDistance
{
    public static int Weighted(ReadOnlySpan<char> a, ReadOnlySpan<char> b, int insertCost = 1, int deleteCost = 1, int substituteCost = 1)
    {
        int n = a.Length, m = b.Length;
        int[,] dp = new int[n + 1, m + 1];
        for (int i = 0; i <= n; i++) dp[i, 0] = i * deleteCost;
        for (int j = 0; j <= m; j++) dp[0, j] = j * insertCost;

        for (int i = 1; i <= n; i++)
        {
            for (int j = 1; j <= m; j++)
            {
                int sub = dp[i - 1, j - 1] + (a[i - 1] == b[j - 1] ? 0 : substituteCost);
                int del = dp[i - 1, j] + deleteCost;
                int ins = dp[i, j - 1] + insertCost;
                dp[i, j] = Math.Min(Math.Min(sub, del), ins);
            }
        }
        return dp[n, m];
    }
}

#endregion

#region Interval Scheduling

public static class IntervalScheduling
{
    public readonly record struct Interval(int Start, int End, int Value);

    public static List<Interval> MaxNonOverlapping(IEnumerable<Interval> intervals)
    {
        var sorted = intervals.OrderBy(i => i.End).ToList();
        var result = new List<Interval>();
        int lastEnd = int.MinValue;

        foreach (var interval in sorted)
        {
            if (interval.Start >= lastEnd)
            {
                result.Add(interval);
                lastEnd = interval.End;
            }
        }
        return result;
    }

    public static int WeightedScheduling(IReadOnlyList<Interval> intervals)
    {
        var sorted = intervals.OrderBy(i => i.End).ToArray();
        int n = sorted.Length;
        int[] dp = new int[n + 1];
        for (int i = 1; i <= n; i++)
        {
            int lastCompatible = FindLastCompatible(sorted, i - 1);
            int include = sorted[i - 1].Value + (lastCompatible >= 0 ? dp[lastCompatible + 1] : 0);
            dp[i] = Math.Max(dp[i - 1], include);
        }
        return dp[n];
    }

    private static int FindLastCompatible(Interval[] intervals, int index)
    {
        for (int i = index - 1; i >= 0; i--)
        {
            if (intervals[i].End <= intervals[index].Start) return i;
        }
        return -1;
    }
}

#endregion

#region Matrix Chain Multiplication

public static class MatrixChain
{
    public static int MinOperations(ReadOnlySpan<int> dims)
    {
        int n = dims.Length - 1;
        int[,] dp = new int[n, n];
        for (int len = 2; len <= n; len++)
        {
            for (int i = 0; i < n - len + 1; i++)
            {
                int j = i + len - 1;
                dp[i, j] = int.MaxValue;
                for (int k = i; k < j; k++)
                {
                    int cost = dp[i, k] + dp[k + 1, j] + dims[i] * dims[k + 1] * dims[j + 1];
                    if (cost < dp[i, j]) dp[i, j] = cost;
                }
            }
        }
        return dp[0, n - 1];
    }
}

#endregion

#region Integer Factorization

public static class Factorization
{
    public static Dictionary<long, int> Factorize(long n)
    {
        var result = new Dictionary<long, int>();
        if (n < 0) { result[-1] = 1; n = -n; }

        while (n % 2 == 0)
        {
            result.TryGetValue(2, out int c);
            result[2] = c + 1;
            n /= 2;
        }

        for (long i = 3; i * i <= n; i += 2)
        {
            while (n % i == 0)
            {
                result.TryGetValue(i, out int c);
                result[i] = c + 1;
                n /= i;
            }
        }

        if (n > 1)
        {
            result.TryGetValue(n, out int c);
            result[n] = c + 1;
        }
        return result;
    }

    public static List<long> Divisors(long n)
    {
        var divisors = new List<long>();
        for (long i = 1; i * i <= n; i++)
        {
            if (n % i == 0)
            {
                divisors.Add(i);
                if (i != n / i) divisors.Add(n / i);
            }
        }
        divisors.Sort();
        return divisors;
    }

    public static long EulerPhi(long n)
    {
        long result = n;
        for (long i = 2; i * i <= n; i++)
        {
            if (n % i == 0)
            {
                while (n % i == 0) n /= i;
                result -= result / i;
            }
        }
        if (n > 1) result -= result / n;
        return result;
    }
}

#endregion

#region Sieve of Eratosthenes

public static class Sieve
{
    public static bool[] PrimesUpTo(int limit)
    {
        bool[] isComposite = new bool[limit + 1];
        if (limit >= 0) isComposite[0] = true;
        if (limit >= 1) isComposite[1] = true;

        for (int i = 2; i * i <= limit; i++)
        {
            if (isComposite[i]) continue;
            for (int j = i * i; j <= limit; j += i)
                isComposite[j] = true;
        }

        bool[] primes = new bool[limit + 1];
        for (int i = 2; i <= limit; i++) primes[i] = !isComposite[i];
        return primes;
    }

    public static int[] SmallestPrimeFactor(int limit)
    {
        int[] spf = new int[limit + 1];
        for (int i = 0; i <= limit; i++) spf[i] = i;
        for (int i = 2; i * i <= limit; i++)
        {
            if (spf[i] != i) continue;
            for (int j = i * i; j <= limit; j += i)
                if (spf[j] == j) spf[j] = i;
        }
        return spf;
    }
}

#endregion

#region Chinese Remainder Theorem

public static class ChineseRemainder
{
    public static long Solve(long[] remainders, long[] moduli)
    {
        long M = 1;
        foreach (long m in moduli) M *= m;

        long result = 0;
        for (int i = 0; i < remainders.Length; i++)
        {
            long Mi = M / moduli[i];
            long inverse = ModInverse(Mi, moduli[i]);
            result = (result + remainders[i] * Mi * inverse) % M;
        }
        return ((result % M) + M) % M;
    }

    private static long ModInverse(long a, long m)
    {
        var (g, x, _) = ExtendedGcd(a, m);
        if (g != 1) throw new InvalidOperationException("no inverse");
        return ((x % m) + m) % m;
    }

    private static (long g, long x, long y) ExtendedGcd(long a, long b)
    {
        if (b == 0) return (a, 1, 0);
        var (g, x1, y1) = ExtendedGcd(b, a % b);
        return (g, y1, x1 - (a / b) * y1);
    }
}

#endregion

#region Karatsuba Multiplication

public static class Karatsuba
{
    public static BigInteger Multiply(BigInteger a, BigInteger b)
    {
        if (a < 10 || b < 10) return a * b;

        int n = Math.Max(a.GetByteCount(), b.GetByteCount()) * 8;
        int half = n / 2;

        BigInteger a1 = a >> half;
        BigInteger a0 = a & ((BigInteger.One << half) - 1);
        BigInteger b1 = b >> half;
        BigInteger b0 = b & ((BigInteger.One << half) - 1);

        BigInteger z0 = Multiply(a0, b0);
        BigInteger z2 = Multiply(a1, b1);
        BigInteger z1 = Multiply(a0 + a1, b0 + b1) - z0 - z2;

        return (z2 << (2 * half)) + (z1 << half) + z0;
    }
}

#endregion

#region Fast Exponentiation

public static class FastPow
{
    public static long ModPow(long baseValue, long exponent, long modulus)
    {
        long result = 1;
        baseValue %= modulus;
        while (exponent > 0)
        {
            if ((exponent & 1) == 1)
                result = (result * baseValue) % modulus;
            baseValue = (baseValue * baseValue) % modulus;
            exponent >>= 1;
        }
        return result;
    }

    public static double Pow(double baseValue, int exponent)
    {
        bool negative = exponent < 0;
        exponent = Math.Abs(exponent);
        double result = 1;
        double current = baseValue;
        while (exponent > 0)
        {
            if ((exponent & 1) == 1) result *= current;
            current *= current;
            exponent >>= 1;
        }
        return negative ? 1.0 / result : result;
    }
}

#endregion

#region N Queens

public static class NQueens
{
    public static List<int[]> Solve(int n)
    {
        var solutions = new List<int[]>();
        var board = new int[n];
        SolveRecursive(board, 0, solutions);
        return solutions;
    }

    private static void SolveRecursive(int[] board, int row, List<int[]> solutions)
    {
        int n = board.Length;
        if (row == n)
        {
            solutions.Add((int[])board.Clone());
            return;
        }

        for (int col = 0; col < n; col++)
        {
            if (IsSafe(board, row, col))
            {
                board[row] = col;
                SolveRecursive(board, row + 1, solutions);
            }
        }
    }

    private static bool IsSafe(int[] board, int row, int col)
    {
        for (int i = 0; i < row; i++)
        {
            if (board[i] == col) return false;
            if (Math.Abs(board[i] - col) == Math.Abs(i - row)) return false;
        }
        return true;
    }

    public static int Count(int n)
    {
        int count = 0;
        var board = new int[n];
        CountRecursive(board, 0, ref count);
        return count;
    }

    private static void CountRecursive(int[] board, int row, ref int count)
    {
        int n = board.Length;
        if (row == n)
        {
            count++;
            return;
        }

        for (int col = 0; col < n; col++)
        {
            if (IsSafe(board, row, col))
            {
                board[row] = col;
                CountRecursive(board, row + 1, ref count);
            }
        }
    }
}

#endregion

#region Sudoku Solver

public static class SudokuSolver
{
    public static bool Solve(int[,] grid)
    {
        var (row, col) = FindEmpty(grid);
        if (row == -1) return true;

        for (int num = 1; num <= 9; num++)
        {
            if (IsValid(grid, row, col, num))
            {
                grid[row, col] = num;
                if (Solve(grid)) return true;
                grid[row, col] = 0;
            }
        }
        return false;
    }

    private static (int row, int col) FindEmpty(int[,] grid)
    {
        for (int r = 0; r < 9; r++)
            for (int c = 0; c < 9; c++)
                if (grid[r, c] == 0) return (r, c);
        return (-1, -1);
    }

    private static bool IsValid(int[,] grid, int row, int col, int num)
    {
        for (int i = 0; i < 9; i++)
        {
            if (grid[row, i] == num) return false;
            if (grid[i, col] == num) return false;
        }

        int boxRow = (row / 3) * 3;
        int boxCol = (col / 3) * 3;
        for (int r = 0; r < 3; r++)
            for (int c = 0; c < 3; c++)
                if (grid[boxRow + r, boxCol + c] == num) return false;

        return true;
    }
}

#endregion

#region Huffman Encoding

public static class HuffmanEncoder
{
    public sealed class Node
    {
        public char? Symbol;
        public int Frequency;
        public Node? Left;
        public Node? Right;
    }

    public static (Dictionary<char, string> codes, Node root) BuildTree(string text)
    {
        var frequencies = new Dictionary<char, int>();
        foreach (char c in text)
        {
            frequencies.TryGetValue(c, out int current);
            frequencies[c] = current + 1;
        }

        var heap = new BinaryHeap<Node>((a, b) => a.Frequency.CompareTo(b.Frequency));
        foreach (var kv in frequencies)
            heap.Push(new Node { Symbol = kv.Key, Frequency = kv.Value });

        while (heap.Count > 1)
        {
            Node left = heap.Pop();
            Node right = heap.Pop();
            heap.Push(new Node
            {
                Frequency = left.Frequency + right.Frequency,
                Left = left,
                Right = right
            });
        }

        Node root = heap.Pop();
        var codes = new Dictionary<char, string>();
        AssignCodes(root, "", codes);
        return (codes, root);
    }

    private static void AssignCodes(Node node, string prefix, Dictionary<char, string> codes)
    {
        if (node.Symbol.HasValue)
        {
            codes[node.Symbol.Value] = prefix.Length == 0 ? "0" : prefix;
            return;
        }
        if (node.Left != null) AssignCodes(node.Left, prefix + "0", codes);
        if (node.Right != null) AssignCodes(node.Right, prefix + "1", codes);
    }
}

#endregion

#region Base58Check

public static class Base58Check
{
    private const string Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

    public static string Encode(ReadOnlySpan<byte> data)
    {
        byte[] checksum = SHA256.HashData(SHA256.HashData(data));
        byte[] payload = new byte[data.Length + 4];
        data.CopyTo(payload);
        Array.Copy(checksum, 0, payload, data.Length, 4);

        BigInteger value = new BigInteger(payload, isUnsigned: true, isBigEndian: true);
        var sb = new StringBuilder();
        while (value > 0)
        {
            int rem = (int)(value % 58);
            sb.Insert(0, Alphabet[rem]);
            value /= 58;
        }

        foreach (byte b in payload)
        {
            if (b == 0) sb.Insert(0, '1');
            else break;
        }
        return sb.ToString();
    }

    public static byte[] Decode(string input)
    {
        BigInteger value = 0;
        foreach (char c in input)
        {
            int idx = Alphabet.IndexOf(c);
            if (idx < 0) throw new FormatException("invalid character");
            value = value * 58 + idx;
        }

        byte[] bytes = value.ToByteArray(isUnsigned: true, isBigEndian: true);
        int leadingZeros = 0;
        foreach (char c in input)
        {
            if (c == '1') leadingZeros++;
            else break;
        }

        byte[] result = new byte[leadingZeros + bytes.Length];
        Array.Copy(bytes, 0, result, leadingZeros, bytes.Length);

        if (result.Length < 4) throw new FormatException("too short");
        byte[] payload = result[..^4];
        byte[] expectedChecksum = result[^4..];
        byte[] actualChecksum = SHA256.HashData(SHA256.HashData(payload));

        for (int i = 0; i < 4; i++)
        {
            if (expectedChecksum[i] != actualChecksum[i])
                throw new FormatException("checksum mismatch");
        }
        return payload;
    }
}

#endregion

#region BIP39 Seed Derivation

public static class Bip39
{
    public static byte[] DeriveSeed(string mnemonic, string passphrase = "")
    {
        string salt = "mnemonic" + passphrase;
        byte[] password = Encoding.UTF8.GetBytes(mnemonic.Normalize(System.Text.NormalizationForm.FormKD));
        byte[] saltBytes = Encoding.UTF8.GetBytes(salt.Normalize(System.Text.NormalizationForm.FormKD));

        using var pbkdf2 = new Rfc2898DeriveBytes(password, saltBytes, 2048, HashAlgorithmName.SHA512);
        return pbkdf2.GetBytes(64);
    }

    public static byte[] DeriveMasterKey(byte[] seed)
    {
        using var hmac = new HMACSHA512(Encoding.UTF8.GetBytes("Bitcoin seed"));
        byte[] hash = hmac.ComputeHash(seed);
        byte[] il = hash[..32];
        byte[] ir = hash[32..];
        byte[] master = new byte[64];
        Array.Copy(il, 0, master, 0, 32);
        Array.Copy(ir, 0, master, 32, 32);
        return master;
    }
}

#endregion

#region Bcrypt Cost

public static class BcryptCost
{
    public static int EstimateIterations(int targetMilliseconds, int sampleIterations = 1000)
    {
        var stopwatch = Stopwatch.StartNew();
        byte[] data = new byte[64];
        using var sha = SHA256.Create();

        for (int i = 0; i < sampleIterations; i++)
        {
            sha.ComputeHash(data);
            data[0] = (byte)i;
        }
        stopwatch.Stop();

        double perIteration = stopwatch.Elapsed.TotalMilliseconds / sampleIterations;
        return (int)(targetMilliseconds / perIteration);
    }
}

#endregion

#region Argon2 Parameters

public static class Argon2Params
{
    public readonly record struct Parameters(
        int MemoryKiB,
        int Iterations,
        int Parallelism,
        int HashLength,
        int SaltLength);

    public static Parameters Interactive => new(
        MemoryKiB: 65536,
        Iterations: 2,
        Parallelism: 1,
        HashLength: 32,
        SaltLength: 16);

    public static Parameters Moderate => new(
        MemoryKiB: 262144,
        Iterations: 3,
        Parallelism: 1,
        HashLength: 32,
        SaltLength: 16);

    public static Parameters Sensitive => new(
        MemoryKiB: 1048576,
        Iterations: 4,
        Parallelism: 4,
        HashLength: 32,
        SaltLength: 32);
}

#endregion

#region Time-Based OTP

public static class Totp
{
    public static string Generate(byte[] secret, int digits = 6, int period = 30, long? timestamp = null)
    {
        long counter = (timestamp ?? DateTimeOffset.UtcNow.ToUnixTimeSeconds()) / period;
        byte[] counterBytes = new byte[8];
        BinaryPrimitives.WriteInt64BigEndian(counterBytes, counter);

        using var hmac = new HMACSHA1(secret);
        byte[] hash = hmac.ComputeHash(counterBytes);
        int offset = hash[^1] & 0x0F;
        int binary = ((hash[offset] & 0x7F) << 24)
                   | ((hash[offset + 1] & 0xFF) << 16)
                   | ((hash[offset + 2] & 0xFF) << 8)
                   | (hash[offset + 3] & 0xFF);
        int otp = binary % (int)Math.Pow(10, digits);
        return otp.ToString(new string('0', digits));
    }

    public static bool Verify(byte[] secret, string code, int window = 1, int digits = 6, int period = 30)
    {
        long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        for (int i = -window; i <= window; i++)
        {
            string expected = Generate(secret, digits, period, now + i * period);
            if (CryptographicOperations.FixedTimeEquals(
                Encoding.ASCII.GetBytes(expected),
                Encoding.ASCII.GetBytes(code)))
            {
                return true;
            }
        }
        return false;
    }
}

#endregion

#region Hotp

public static class Hotp
{
    public static string Generate(byte[] secret, long counter, int digits = 6)
    {
        byte[] counterBytes = new byte[8];
        BinaryPrimitives.WriteInt64BigEndian(counterBytes, counter);
        using var hmac = new HMACSHA1(secret);
        byte[] hash = hmac.ComputeHash(counterBytes);
        int offset = hash[^1] & 0x0F;
        int binary = ((hash[offset] & 0x7F) << 24)
                   | ((hash[offset + 1] & 0xFF) << 16)
                   | ((hash[offset + 2] & 0xFF) << 8)
                   | (hash[offset + 3] & 0xFF);
        int otp = binary % (int)Math.Pow(10, digits);
        return otp.ToString(new string('0', digits));
    }
}

#endregion

#region Bloom Filter Counting

public sealed class CountingBloomFilter
{
    private readonly byte[] _counters;
    private readonly int _hashCount;
    private readonly int _size;

    public CountingBloomFilter(int size, int hashCount = 4)
    {
        _size = size;
        _hashCount = hashCount;
        _counters = new byte[size];
    }

    public void Add(ReadOnlySpan<byte> item)
    {
        ulong h1 = BitMath.Fnv1a(item);
        ulong h2 = BitMath.Murmur(h1);

        for (int i = 0; i < _hashCount; i++)
        {
            int index = (int)((h1 + (ulong)i * h2) % (ulong)_size);
            if (_counters[index] < byte.MaxValue) _counters[index]++;
        }
    }

    public bool Contains(ReadOnlySpan<byte> item)
    {
        ulong h1 = BitMath.Fnv1a(item);
        ulong h2 = BitMath.Murmur(h1);

        for (int i = 0; i < _hashCount; i++)
        {
            int index = (int)((h1 + (ulong)i * h2) % (ulong)_size);
            if (_counters[index] == 0) return false;
        }
        return true;
    }

    public void Remove(ReadOnlySpan<byte> item)
    {
        if (!Contains(item)) return;

        ulong h1 = BitMath.Fnv1a(item);
        ulong h2 = BitMath.Murmur(h1);

        for (int i = 0; i < _hashCount; i++)
        {
            int index = (int)((h1 + (ulong)i * h2) % (ulong)_size);
            if (_counters[index] > 0) _counters[index]--;
        }
    }
}

#endregion

#region Min Heap

public sealed class MinHeap<T> where T : IComparable<T>
{
    private readonly List<T> _items = new();

    public int Count => _items.Count;
    public bool IsEmpty => _items.Count == 0;

    public void Push(T item)
    {
        _items.Add(item);
        SiftUp(_items.Count - 1);
    }

    public T Pop()
    {
        if (_items.Count == 0) throw new InvalidOperationException("heap is empty");
        T result = _items[0];
        int last = _items.Count - 1;
        _items[0] = _items[last];
        _items.RemoveAt(last);
        if (_items.Count > 0) SiftDown(0);
        return result;
    }

    public T Peek()
    {
        if (_items.Count == 0) throw new InvalidOperationException("heap is empty");
        return _items[0];
    }

    private void SiftUp(int index)
    {
        while (index > 0)
        {
            int parent = (index - 1) / 2;
            if (_items[index].CompareTo(_items[parent]) >= 0) break;
            (_items[index], _items[parent]) = (_items[parent], _items[index]);
            index = parent;
        }
    }

    private void SiftDown(int index)
    {
        int count = _items.Count;
        while (true)
        {
            int left = 2 * index + 1;
            int right = 2 * index + 2;
            int smallest = index;

            if (left < count && _items[left].CompareTo(_items[smallest]) < 0) smallest = left;
            if (right < count && _items[right].CompareTo(_items[smallest]) < 0) smallest = right;
            if (smallest == index) break;

            (_items[index], _items[smallest]) = (_items[smallest], _items[index]);
            index = smallest;
        }
    }
}

#endregion

#region D-ary Heap

public sealed class DAryHeap<T>
{
    private readonly List<T> _items = new();
    private readonly int _arity;
    private readonly Comparison<T> _comparison;

    public DAryHeap(int arity, Comparison<T> comparison)
    {
        if (arity < 2) throw new ArgumentOutOfRangeException(nameof(arity));
        _arity = arity;
        _comparison = comparison;
    }

    public int Count => _items.Count;
    public bool IsEmpty => _items.Count == 0;

    public void Push(T item)
    {
        _items.Add(item);
        SiftUp(_items.Count - 1);
    }

    public T Pop()
    {
        if (_items.Count == 0) throw new InvalidOperationException("empty");
        T result = _items[0];
        int last = _items.Count - 1;
        _items[0] = _items[last];
        _items.RemoveAt(last);
        if (_items.Count > 0) SiftDown(0);
        return result;
    }

    private void SiftUp(int index)
    {
        while (index > 0)
        {
            int parent = (index - 1) / _arity;
            if (_comparison(_items[index], _items[parent]) >= 0) break;
            (_items[index], _items[parent]) = (_items[parent], _items[index]);
            index = parent;
        }
    }

    private void SiftDown(int index)
    {
        int count = _items.Count;
        while (true)
        {
            int firstChild = _arity * index + 1;
            if (firstChild >= count) break;

            int smallest = index;
            for (int i = 0; i < _arity && firstChild + i < count; i++)
            {
                if (_comparison(_items[firstChild + i], _items[smallest]) < 0)
                    smallest = firstChild + i;
            }

            if (smallest == index) break;
            (_items[index], _items[smallest]) = (_items[smallest], _items[index]);
            index = smallest;
        }
    }
}

#endregion

#region Fibonacci Heap Node

public sealed class FibonacciHeap<T> where T : IComparable<T>
{
    private sealed class Node
    {
        public T Key = default!;
        public int Degree;
        public bool Marked;
        public Node? Parent;
        public Node? Child;
        public Node? Left;
        public Node? Right;
    }

    private Node? _min;
    private int _count;

    public int Count => _count;
    public bool IsEmpty => _min == null;

    public void Insert(T key)
    {
        var node = new Node { Key = key };
        node.Left = node;
        node.Right = node;

        if (_min == null)
        {
            _min = node;
        }
        else
        {
            InsertIntoList(_min, node);
            if (node.Key.CompareTo(_min.Key) < 0) _min = node;
        }
        _count++;
    }

    public T ExtractMin()
    {
        if (_min == null) throw new InvalidOperationException("empty");
        Node minNode = _min;

        if (minNode.Child != null)
        {
            var child = minNode.Child;
            do
            {
                var next = child.Right;
                child.Parent = null;
                InsertIntoList(_min, child!);
                child = next;
            } while (child != minNode.Child);
        }

        RemoveFromList(minNode);
        if (minNode == minNode.Right)
        {
            _min = null;
        }
        else
        {
            _min = minNode.Right;
            Consolidate();
        }
        _count--;
        return minNode.Key;
    }

    private static void InsertIntoList(Node head, Node node)
    {
        node.Left = head.Left;
        node.Right = head;
        head.Left!.Right = node;
        head.Left = node;
    }

    private static void RemoveFromList(Node node)
    {
        node.Left!.Right = node.Right;
        node.Right!.Left = node.Left;
    }

    private void Consolidate()
    {
        var rootList = new List<Node>();
        var current = _min!;
        do
        {
            rootList.Add(current);
            current = current.Right!;
        } while (current != _min);

        var degreeTable = new Dictionary<int, Node>();
        foreach (var root in rootList)
        {
            var node = root;
            while (degreeTable.TryGetValue(node.Degree, out var existing))
            {
                Node min = node.Key.CompareTo(existing.Key) < 0 ? node : existing;
                Node max = min == node ? existing : node;
                RemoveFromList(max);
                max.Parent = min;
                max.Marked = false;
                max.Left = max;
                max.Right = max;

                if (min.Child == null)
                {
                    min.Child = max;
                }
                else
                {
                    InsertIntoList(min.Child, max);
                }
                min.Degree++;

                degreeTable.Remove(node.Degree);
                node = min;
            }
            degreeTable[node.Degree] = node;
            if (node.Key.CompareTo(_min!.Key) < 0) _min = node;
        }
    }
}

#endregion

#region Red Black Tree

public sealed class RedBlackTree<TKey, TValue> where TKey : IComparable<TKey>
{
    private enum Color { Red, Black }

    private sealed class Node
    {
        public TKey Key = default!;
        public TValue Value = default!;
        public Color Color = Color.Red;
        public Node? Parent;
        public Node? Left;
        public Node? Right;
    }

    private Node? _root;
    private int _count;

    public int Count => _count;

    public void Insert(TKey key, TValue value)
    {
        Node? parent = null;
        var current = _root;

        while (current != null)
        {
            parent = current;
            int cmp = key.CompareTo(current.Key);
            if (cmp == 0)
            {
                current.Value = value;
                return;
            }
            current = cmp < 0 ? current.Left : current.Right;
        }

        var node = new Node { Key = key, Value = value, Parent = parent };
        if (parent == null) _root = node;
        else if (key.CompareTo(parent.Key) < 0) parent.Left = node;
        else parent.Right = node;

        _count++;
        InsertFixup(node);
    }

    private void InsertFixup(Node node)
    {
        while (node.Parent?.Color == Color.Red)
        {
            var parent = node.Parent;
            var grandparent = parent.Parent!;

            if (parent == grandparent.Left)
            {
                var uncle = grandparent.Right;
                if (uncle?.Color == Color.Red)
                {
                    parent.Color = Color.Black;
                    uncle.Color = Color.Black;
                    grandparent.Color = Color.Red;
                    node = grandparent;
                }
                else
                {
                    if (node == parent.Right)
                    {
                        node = parent;
                        RotateLeft(node);
                    }
                    parent.Color = Color.Black;
                    grandparent.Color = Color.Red;
                    RotateRight(grandparent);
                }
            }
            else
            {
                var uncle = grandparent.Left;
                if (uncle?.Color == Color.Red)
                {
                    parent.Color = Color.Black;
                    uncle.Color = Color.Black;
                    grandparent.Color = Color.Red;
                    node = grandparent;
                }
                else
                {
                    if (node == parent.Left)
                    {
                        node = parent;
                        RotateRight(node);
                    }
                    parent.Color = Color.Black;
                    grandparent.Color = Color.Red;
                    RotateLeft(grandparent);
                }
            }
        }
        _root!.Color = Color.Black;
    }

    private void RotateLeft(Node x)
    {
        var y = x.Right!;
        x.Right = y.Left;
        if (y.Left != null) y.Left.Parent = x;
        y.Parent = x.Parent;

        if (x.Parent == null) _root = y;
        else if (x == x.Parent.Left) x.Parent.Left = y;
        else x.Parent.Right = y;

        y.Left = x;
        x.Parent = y;
    }

    private void RotateRight(Node y)
    {
        var x = y.Left!;
        y.Left = x.Right;
        if (x.Right != null) x.Right.Parent = y;
        x.Parent = y.Parent;

        if (y.Parent == null) _root = x;
        else if (y == y.Parent.Right) y.Parent.Right = x;
        else y.Parent.Left = x;

        x.Right = y;
        y.Parent = x;
    }

    public bool TryGet(TKey key, out TValue? value)
    {
        var current = _root;
        while (current != null)
        {
            int cmp = key.CompareTo(current.Key);
            if (cmp == 0)
            {
                value = current.Value;
                return true;
            }
            current = cmp < 0 ? current.Left : current.Right;
        }
        value = default;
        return false;
    }
}

#endregion

#region AVL Tree

public sealed class AvlTree<TKey> where TKey : IComparable<TKey>
{
    private sealed class Node
    {
        public TKey Key = default!;
        public int Height = 1;
        public Node? Left;
        public Node? Right;
    }

    private Node? _root;

    public void Insert(TKey key) => _root = InsertRecursive(_root, key);

    private static Node InsertRecursive(Node? node, TKey key)
    {
        if (node == null) return new Node { Key = key };
        int cmp = key.CompareTo(node.Key);
        if (cmp < 0) node.Left = InsertRecursive(node.Left, key);
        else if (cmp > 0) node.Right = InsertRecursive(node.Right, key);
        else return node;

        node.Height = 1 + Math.Max(Height(node.Left), Height(node.Right));
        int balance = BalanceFactor(node);

        if (balance > 1 && key.CompareTo(node.Left!.Key) < 0)
            return RotateRight(node);

        if (balance < -1 && key.CompareTo(node.Right!.Key) > 0)
            return RotateLeft(node);

        if (balance > 1 && key.CompareTo(node.Left!.Key) > 0)
        {
            node.Left = RotateLeft(node.Left!);
            return RotateRight(node);
        }

        if (balance < -1 && key.CompareTo(node.Right!.Key) < 0)
        {
            node.Right = RotateRight(node.Right!);
            return RotateLeft(node);
        }

        return node;
    }

    private static int Height(Node? node) => node?.Height ?? 0;
    private static int BalanceFactor(Node node) => Height(node.Left) - Height(node.Right);

    private static Node RotateRight(Node y)
    {
        Node x = y.Left!;
        Node t2 = x.Right!;
        x.Right = y;
        y.Left = t2;
        y.Height = 1 + Math.Max(Height(y.Left), Height(y.Right));
        x.Height = 1 + Math.Max(Height(x.Left), Height(x.Right));
        return x;
    }

    private static Node RotateLeft(Node x)
    {
        Node y = x.Right!;
        Node t2 = y.Left!;
        y.Left = x;
        x.Right = t2;
        x.Height = 1 + Math.Max(Height(x.Left), Height(x.Right));
        y.Height = 1 + Math.Max(Height(y.Left), Height(y.Right));
        return y;
    }

    public bool Contains(TKey key)
    {
        var current = _root;
        while (current != null)
        {
            int cmp = key.CompareTo(current.Key);
            if (cmp == 0) return true;
            current = cmp < 0 ? current.Left : current.Right;
        }
        return false;
    }
}

#endregion

#region Merkle Tree

public sealed class MerkleTree
{
    private readonly List<byte[]> _leaves = new();
    private readonly List<List<byte[]>> _levels = new();

    public void Add(ReadOnlySpan<byte> data) => _leaves.Add(SHA256.HashData(data));

    public byte[] Build()
    {
        if (_leaves.Count == 0) return Array.Empty<byte>();

        _levels.Clear();
        var current = new List<byte[]>(_leaves.Select(h => h.ToArray()));
        _levels.Add(current);

        while (current.Count > 1)
        {
            var next = new List<byte[]>();
            for (int i = 0; i < current.Count; i += 2)
            {
                byte[] left = current[i];
                byte[] right = i + 1 < current.Count ? current[i + 1] : left;
                byte[] combined = new byte[left.Length + right.Length];
                Array.Copy(left, 0, combined, 0, left.Length);
                Array.Copy(right, 0, combined, left.Length, right.Length);
                next.Add(SHA256.HashData(combined));
            }
            _levels.Add(next);
            current = next;
        }

        return current[0];
    }

    public IReadOnlyList<byte[]> GetProof(int index)
    {
        var proof = new List<byte[]>();
        int currentIndex = index;

        for (int level = 0; level < _levels.Count - 1; level++)
        {
            var nodes = _levels[level];
            int siblingIndex = currentIndex % 2 == 0 ? currentIndex + 1 : currentIndex - 1;

            if (siblingIndex < nodes.Count)
                proof.Add(nodes[siblingIndex]);
            else
                proof.Add(nodes[currentIndex]);

            currentIndex /= 2;
        }

        return proof;
    }

    public static bool Verify(ReadOnlySpan<byte> leaf, IReadOnlyList<byte[]> proof, byte[] root)
    {
        byte[] hash = SHA256.HashData(leaf);
        foreach (byte[] sibling in proof)
        {
            byte[] combined = new byte[hash.Length + sibling.Length];
            Array.Copy(hash, 0, combined, 0, hash.Length);
            Array.Copy(sibling, 0, combined, hash.Length, sibling.Length);
            hash = SHA256.HashData(combined);
        }
        return CryptographicOperations.FixedTimeEquals(hash, root);
    }
}

#endregion

#region SipHash

public static class SipHash
{
    private const ulong V0_INIT = 0x736F6D6570736575UL;
    private const ulong V1_INIT = 0x646F72616E646F6DUL;
    private const ulong V2_INIT = 0x6C7967656E657261UL;
    private const ulong V3_INIT = 0x7465646279746573UL;

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void Round(ref ulong v0, ref ulong v1, ref ulong v2, ref ulong v3)
    {
        v0 += v1;
        v1 = BitOperations.RotateLeft(v1, 13);
        v1 ^= v0;
        v0 = BitOperations.RotateLeft(v0, 32);
        v2 += v3;
        v3 = BitOperations.RotateLeft(v3, 16);
        v3 ^= v2;
        v0 += v3;
        v3 = BitOperations.RotateLeft(v3, 21);
        v3 ^= v0;
        v2 += v1;
        v1 = BitOperations.RotateLeft(v1, 17);
        v1 ^= v2;
        v2 = BitOperations.RotateLeft(v2, 32);
    }

    public static ulong Compute(ReadOnlySpan<byte> data, ulong k0, ulong k1)
    {
        ulong v0 = k0 ^ V0_INIT;
        ulong v1 = k1 ^ V1_INIT;
        ulong v2 = k0 ^ V2_INIT;
        ulong v3 = k1 ^ V3_INIT;

        int length = data.Length;
        int i = 0;
        while (i + 8 <= length)
        {
            ulong m = BinaryPrimitives.ReadUInt64LittleEndian(data.Slice(i));
            v3 ^= m;
            Round(ref v0, ref v1, ref v2, ref v3);
            Round(ref v0, ref v1, ref v2, ref v3);
            v0 ^= m;
            i += 8;
        }

        ulong last = (ulong)length << 56;
        int remaining = length - i;
        for (int j = 0; j < remaining; j++)
        {
            last |= (ulong)data[i + j] << (8 * j);
        }

        v3 ^= last;
        Round(ref v0, ref v1, ref v2, ref v3);
        Round(ref v0, ref v1, ref v2, ref v3);
        v0 ^= last;

        v2 ^= 0xFF;
        Round(ref v0, ref v1, ref v2, ref v3);
        Round(ref v0, ref v1, ref v2, ref v3);
        Round(ref v0, ref v1, ref v2, ref v3);
        Round(ref v0, ref v1, ref v2, ref v3);

        return v0 ^ v1 ^ v2 ^ v3;
    }
}

#endregion

#region HighwayHash

public static class HighwayHash
{
    private const int NumLanes = 4;
    private const int NumRounds = 4;

    public static ulong[] Hash(ReadOnlySpan<byte> data, ulong[] key)
    {
        if (key.Length != 4) throw new ArgumentException("key must have 4 lanes");

        ulong[] state = new ulong[4];
        for (int i = 0; i < 4; i++) state[i] = key[i];

        int i2 = 0;
        while (i2 + 32 <= data.Length)
        {
            ulong m0 = BinaryPrimitives.ReadUInt64LittleEndian(data.Slice(i2));
            ulong m1 = BinaryPrimitives.ReadUInt64LittleEndian(data.Slice(i2 + 8));
            ulong m2 = BinaryPrimitives.ReadUInt64LittleEndian(data.Slice(i2 + 16));
            ulong m3 = BinaryPrimitives.ReadUInt64LittleEndian(data.Slice(i2 + 24));

            state[0] += m0;
            state[1] += m1;
            state[2] += m2;
            state[3] += m3;

            Mix(ref state);
            i2 += 32;
        }

        return state;
    }

    private static void Mix(ref ulong[] v)
    {
        for (int round = 0; round < NumRounds; round++)
        {
            v[0] += v[1]; v[1] = BitOperations.RotateLeft(v[1], 13); v[1] ^= v[0];
            v[0] = BitOperations.RotateLeft(v[0], 32);
            v[2] += v[3]; v[3] = BitOperations.RotateLeft(v[3], 16); v[3] ^= v[2];
            v[0] += v[3]; v[3] = BitOperations.RotateLeft(v[3], 21); v[3] ^= v[0];
            v[2] += v[1]; v[1] = BitOperations.RotateLeft(v[1], 17); v[1] ^= v[2];
            v[2] = BitOperations.RotateLeft(v[2], 32);
        }
    }
}

#endregion

#region XXHash64

public static class XxHash64
{
    private const ulong Prime1 = 11400714785074694791UL;
    private const ulong Prime2 = 14029467366897019727UL;
    private const ulong Prime3 = 1609587929392839161UL;
    private const ulong Prime4 = 9650029242287828579UL;
    private const ulong Prime5 = 2870177450012600261UL;

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static ulong Round(ulong acc, ulong input)
    {
        acc += input * Prime2;
        acc = BitOperations.RotateLeft(acc, 31);
        acc *= Prime1;
        return acc;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static ulong MergeRound(ulong acc, ulong val)
    {
        val = Round(0, val);
        acc ^= val;
        acc = acc * Prime1 + Prime4;
        return acc;
    }

    public static ulong Compute(ReadOnlySpan<byte> data, ulong seed = 0)
    {
        int len = data.Length;
        ulong h64;

        if (len >= 32)
        {
            ulong v1 = seed + Prime1 + Prime2;
            ulong v2 = seed + Prime2;
            ulong v3 = seed;
            ulong v4 = seed - Prime1;

            int i = 0;
            while (i + 32 <= len)
            {
                v1 = Round(v1, BinaryPrimitives.ReadUInt64LittleEndian(data.Slice(i)));
                v2 = Round(v2, BinaryPrimitives.ReadUInt64LittleEndian(data.Slice(i + 8)));
                v3 = Round(v3, BinaryPrimitives.ReadUInt64LittleEndian(data.Slice(i + 16)));
                v4 = Round(v4, BinaryPrimitives.ReadUInt64LittleEndian(data.Slice(i + 24)));
                i += 32;
            }

            h64 = BitOperations.RotateLeft(v1, 1) + BitOperations.RotateLeft(v2, 7)
                + BitOperations.RotateLeft(v3, 12) + BitOperations.RotateLeft(v4, 18);

            h64 = MergeRound(h64, v1);
            h64 = MergeRound(h64, v2);
            h64 = MergeRound(h64, v3);
            h64 = MergeRound(h64, v4);

            while (i + 8 <= len)
            {
                h64 ^= Round(0, BinaryPrimitives.ReadUInt64LittleEndian(data.Slice(i)));
                h64 = BitOperations.RotateLeft(h64, 27) * Prime1 + Prime4;
                i += 8;
            }

            while (i < len)
            {
                h64 ^= data[i] * Prime5;
                h64 = BitOperations.RotateLeft(h64, 11) * Prime1;
                i++;
            }
        }
        else
        {
            h64 = seed + Prime5;
            int i = 0;
            while (i + 8 <= len)
            {
                h64 ^= Round(0, BinaryPrimitives.ReadUInt64LittleEndian(data.Slice(i)));
                h64 = BitOperations.RotateLeft(h64, 27) * Prime1 + Prime4;
                i += 8;
            }
            while (i < len)
            {
                h64 ^= data[i] * Prime5;
                h64 = BitOperations.RotateLeft(h64, 11) * Prime1;
                i++;
            }
        }

        h64 ^= (ulong)len;
        h64 ^= h64 >> 33;
        h64 *= Prime2;
        h64 ^= h64 >> 29;
        h64 *= Prime3;
        h64 ^= h64 >> 32;

        return h64;
    }
}

#endregion

#region WyHash

public static class WyHash
{
    private const ulong Secret0 = 0xA0761D6478BD642FUL;
    private const ulong Secret1 = 0xE7037ED1A0B428DBUL;
    private const ulong Secret2 = 0x8EBC6AF09C88C6E3UL;
    private const ulong Secret3 = 0x589965CC75374CC3UL;

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static ulong Mum(ulong a, ulong b)
    {
        UInt128 r = (UInt128)a * b;
        return (ulong)(r >> 64) ^ (ulong)r;
    }

    public static ulong Compute(ReadOnlySpan<byte> data, ulong seed = 0)
    {
        ulong a = seed ^ Secret0;
        ulong b = Secret1;
        ulong c = Secret2;

        int len = data.Length;
        int i = 0;

        while (len >= 16)
        {
            a = Mum(BinaryPrimitives.ReadUInt64LittleEndian(data.Slice(i)) ^ a,
                    BinaryPrimitives.ReadUInt64LittleEndian(data.Slice(i + 8)) ^ b);
            i += 16;
            len -= 16;
        }

        if (len >= 8)
        {
            a = Mum(BinaryPrimitives.ReadUInt64LittleEndian(data.Slice(i)) ^ a, b);
            i += 8;
            len -= 8;
        }

        if (len > 0)
        {
            ulong tail = 0;
            for (int j = 0; j < len; j++)
                tail = (tail << 8) | data[i + j];
            a = Mum(tail ^ a, c);
        }

        return Mum(a ^ Secret3, b ^ c);
    }
}

#endregion

#region Binary Search

public static class BinarySearch
{
    public static int LowerBound<T>(ReadOnlySpan<T> span, T value) where T : IComparable<T>
    {
        int lo = 0, hi = span.Length;
        while (lo < hi)
        {
            int mid = lo + ((hi - lo) >> 1);
            if (span[mid].CompareTo(value) < 0) lo = mid + 1;
            else hi = mid;
        }
        return lo;
    }

    public static int UpperBound<T>(ReadOnlySpan<T> span, T value) where T : IComparable<T>
    {
        int lo = 0, hi = span.Length;
        while (lo < hi)
        {
            int mid = lo + ((hi - lo) >> 1);
            if (span[mid].CompareTo(value) <= 0) lo = mid + 1;
            else hi = mid;
        }
        return lo;
    }

    public static int TernarySearch<T>(ReadOnlySpan<T> span, T value) where T : IComparable<T>
    {
        int lo = 0, hi = span.Length - 1;
        while (lo <= hi)
        {
            int mid1 = lo + (hi - lo) / 3;
            int mid2 = hi - (hi - lo) / 3;

            int cmp1 = span[mid1].CompareTo(value);
            int cmp2 = span[mid2].CompareTo(value);

            if (cmp1 == 0) return mid1;
            if (cmp2 == 0) return mid2;

            if (cmp1 > 0) hi = mid1 - 1;
            else if (cmp2 < 0) lo = mid2 + 1;
            else { lo = mid1 + 1; hi = mid2 - 1; }
        }
        return -1;
    }

    public static int Exponential<T>(ReadOnlySpan<T> span, T value) where T : IComparable<T>
    {
        if (span.Length == 0) return -1;
        if (span[0].CompareTo(value) == 0) return 0;

        int bound = 1;
        while (bound < span.Length && span[bound].CompareTo(value) < 0)
            bound <<= 1;

        int lo = bound >> 1;
        int hi = Math.Min(bound, span.Length - 1);
        while (lo <= hi)
        {
            int mid = lo + (hi - lo) / 2;
            int cmp = span[mid].CompareTo(value);
            if (cmp == 0) return mid;
            if (cmp < 0) lo = mid + 1;
            else hi = mid - 1;
        }
        return -1;
    }
}

#endregion

#region Sorting

public static class Sorting
{
    private const int InsertionThreshold = 16;

    public static void IntroSort<T>(Span<T> span) where T : IComparable<T>
    {
        int maxDepth = 2 * (int)Math.Floor(Math.Log2(Math.Max(1, span.Length)));
        IntroSortRecursive(span, maxDepth);
    }

    private static void IntroSortRecursive<T>(Span<T> span, int depthLimit) where T : IComparable<T>
    {
        while (span.Length > InsertionThreshold)
        {
            if (depthLimit == 0)
            {
                HeapSort(span);
                return;
            }
            depthLimit--;

            int pivot = Partition(span);
            if (pivot < span.Length - pivot - 1)
            {
                IntroSortRecursive(span[..pivot], depthLimit);
                span = span[(pivot + 1)..];
            }
            else
            {
                IntroSortRecursive(span[(pivot + 1)..], depthLimit);
                span = span[..pivot];
            }
        }
        InsertionSort(span);
    }

    private static int Partition<T>(Span<T> span) where T : IComparable<T>
    {
        int mid = span.Length / 2;
        T pivot = MedianOfThree(span[0], span[mid], span[^1]);

        int i = -1;
        int j = span.Length;
        while (true)
        {
            do { i++; } while (span[i].CompareTo(pivot) < 0);
            do { j--; } while (span[j].CompareTo(pivot) > 0);
            if (i >= j) return j;
            (span[i], span[j]) = (span[j], span[i]);
        }
    }

    private static T MedianOfThree<T>(T a, T b, T c) where T : IComparable<T>
    {
        if (a.CompareTo(b) > 0) (a, b) = (b, a);
        if (b.CompareTo(c) > 0) (b, c) = (c, b);
        if (a.CompareTo(b) > 0) (a, b) = (b, a);
        return b;
    }

    public static void InsertionSort<T>(Span<T> span) where T : IComparable<T>
    {
        for (int i = 1; i < span.Length; i++)
        {
            T key = span[i];
            int j = i - 1;
            while (j >= 0 && span[j].CompareTo(key) > 0)
            {
                span[j + 1] = span[j];
                j--;
            }
            span[j + 1] = key;
        }
    }

    public static void HeapSort<T>(Span<T> span) where T : IComparable<T>
    {
        int n = span.Length;
        for (int i = n / 2 - 1; i >= 0; i--) SiftDown(span, n, i);
        for (int i = n - 1; i > 0; i--)
        {
            (span[0], span[i]) = (span[i], span[0]);
            SiftDown(span, i, 0);
        }
    }

    private static void SiftDown<T>(Span<T> span, int n, int i) where T : IComparable<T>
    {
        while (true)
        {
            int largest = i;
            int left = 2 * i + 1;
            int right = 2 * i + 2;

            if (left < n && span[left].CompareTo(span[largest]) > 0) largest = left;
            if (right < n && span[right].CompareTo(span[largest]) > 0) largest = right;
            if (largest == i) break;

            (span[i], span[largest]) = (span[largest], span[i]);
            i = largest;
        }
    }

    public static void MergeSort<T>(Span<T> span) where T : IComparable<T>
    {
        if (span.Length < 2) return;
        T[] buffer = new T[span.Length];
        MergeSortRecursive(span, buffer);
    }

    private static void MergeSortRecursive<T>(Span<T> span, Span<T> buffer) where T : IComparable<T>
    {
        if (span.Length < 2) return;
        int mid = span.Length / 2;
        MergeSortRecursive(span[..mid], buffer[..mid]);
        MergeSortRecursive(span[mid..], buffer[mid..]);
        Merge(span[..mid], span[mid..], buffer);
        buffer[..span.Length].CopyTo(span);
    }

    private static void Merge<T>(ReadOnlySpan<T> left, ReadOnlySpan<T> right, Span<T> buffer) where T : IComparable<T>
    {
        int i = 0, j = 0, k = 0;
        while (i < left.Length && j < right.Length)
        {
            if (left[i].CompareTo(right[j]) <= 0) buffer[k++] = left[i++];
            else buffer[k++] = right[j++];
        }
        while (i < left.Length) buffer[k++] = left[i++];
        while (j < right.Length) buffer[k++] = right[j++];
    }

    public static void CountingSort(Span<int> span, int maxValue)
    {
        int[] counts = new int[maxValue + 1];
        foreach (int v in span) counts[v]++;
        int index = 0;
        for (int i = 0; i <= maxValue; i++)
        {
            for (int j = 0; j < counts[i]; j++)
                span[index++] = i;
        }
    }

    public static void RadixSort(Span<uint> span)
    {
        const int Bits = 8;
        const int Buckets = 1 << Bits;
        uint[] temp = new uint[span.Length];
        int[] counts = new int[Buckets];

        for (int shift = 0; shift < 32; shift += Bits)
        {
            Array.Clear(counts);
            foreach (uint v in span) counts[(v >> shift) & (Buckets - 1)]++;
            int sum = 0;
            for (int i = 0; i < Buckets; i++)
            {
                int c = counts[i];
                counts[i] = sum;
                sum += c;
            }
            foreach (uint v in span) temp[counts[(v >> shift) & (Buckets - 1)]++] = v;
            temp.AsSpan().CopyTo(span);
        }
    }
}

#endregion

#region Order Statistics

public static class OrderStatistics
{
    public static T QuickSelect<T>(Span<T> span, int k) where T : IComparable<T>
    {
        if (k < 0 || k >= span.Length) throw new ArgumentOutOfRangeException(nameof(k));
        return QuickSelectRecursive(span, k);
    }

    private static T QuickSelectRecursive<T>(Span<T> span, int k) where T : IComparable<T>
    {
        if (span.Length == 1) return span[0];
        int pivot = Partition(span);
        if (k == pivot) return span[pivot];
        return k < pivot
            ? QuickSelectRecursive(span[..pivot], k)
            : QuickSelectRecursive(span[(pivot + 1)..], k - pivot - 1);
    }

    private static int Partition<T>(Span<T> span) where T : IComparable<T>
    {
        T pivot = span[^1];
        int i = -1;
        for (int j = 0; j < span.Length - 1; j++)
        {
            if (span[j].CompareTo(pivot) <= 0)
            {
                i++;
                (span[i], span[j]) = (span[j], span[i]);
            }
        }
        (span[i + 1], span[^1]) = (span[^1], span[i + 1]);
        return i + 1;
    }
}

#endregion

#region Text Diff

public static class TextDiff
{
    public static string Unified(string oldText, string newText, int contextLines = 3)
    {
        var oldLines = oldText.Split('\n');
        var newLines = newText.Split('\n');
        var lcs = LongestCommonSubsequence(oldLines, newLines);

        var sb = new StringBuilder();
        sb.AppendLine("--- old");
        sb.AppendLine("+++ new");

        int oi = 0, ni = 0;
        foreach (var (oldIdx, newIdx) in lcs)
        {
            while (oi < oldIdx) sb.AppendLine($"-{oldLines[oi++]}");
            while (ni < newIdx) sb.AppendLine($"+{newLines[ni++]}");
            sb.AppendLine($" {oldLines[oldIdx]}");
            oi = oldIdx + 1;
            ni = newIdx + 1;
        }
        while (oi < oldLines.Length) sb.AppendLine($"-{oldLines[oi++]}");
        while (ni < newLines.Length) sb.AppendLine($"+{newLines[ni++]}");

        return sb.ToString();
    }

    private static List<(int, int)> LongestCommonSubsequence(string[] a, string[] b)
    {
        int n = a.Length, m = b.Length;
        int[,] dp = new int[n + 1, m + 1];
        for (int i = 1; i <= n; i++)
        {
            for (int j = 1; j <= m; j++)
            {
                if (a[i - 1] == b[j - 1]) dp[i, j] = dp[i - 1, j - 1] + 1;
                else dp[i, j] = Math.Max(dp[i - 1, j], dp[i, j - 1]);
            }
        }

        var result = new List<(int, int)>();
        int x = n, y = m;
        while (x > 0 && y > 0)
        {
            if (a[x - 1] == b[y - 1])
            {
                result.Add((x - 1, y - 1));
                x--;
                y--;
            }
            else if (dp[x - 1, y] >= dp[x, y - 1]) x--;
            else y--;
        }
        result.Reverse();
        return result;
    }
}

#endregion

#region Levenshtein Automaton

public static class LevenshteinAutomaton
{
    public static bool Match(string text, string pattern, int maxDistance)
    {
        int n = text.Length;
        int m = pattern.Length;
        if (Math.Abs(n - m) > maxDistance) return false;

        int[] current = new int[m + 1];
        int[] previous = new int[m + 1];
        for (int j = 0; j <= m; j++) previous[j] = j;

        for (int i = 1; i <= n; i++)
        {
            current[0] = i;
            int rowMin = current[0];

            for (int j = 1; j <= m; j++)
            {
                int cost = text[i - 1] == pattern[j - 1] ? 0 : 1;
                current[j] = Math.Min(
                    Math.Min(current[j - 1] + 1, previous[j] + 1),
                    previous[j - 1] + cost);
                if (current[j] < rowMin) rowMin = current[j];
            }

            if (rowMin > maxDistance) return false;
            (previous, current) = (current, previous);
        }

        return previous[m] <= maxDistance;
    }
}

#endregion

#region Patricia Trie

public sealed class PatriciaTrie
{
    private sealed class Node
    {
        public string Prefix = "";
        public Dictionary<char, Node> Children = new();
        public bool IsEnd;
    }

    private readonly Node _root = new();

    public void Insert(string word)
    {
        var node = _root;
        int i = 0;
        while (i < word.Length)
        {
            char c = word[i];
            if (!node.Children.TryGetValue(c, out var child))
            {
                var leaf = new Node { Prefix = word[i..], IsEnd = true };
                node.Children[c] = leaf;
                return;
            }

            int common = CommonPrefixLength(child.Prefix, word[i..]);
            if (common == child.Prefix.Length)
            {
                i += common;
                node = child;
            }
            else
            {
                var split = new Node { Prefix = child.Prefix[..common] };
                var remainder = new Node
                {
                    Prefix = child.Prefix[common..],
                    IsEnd = child.IsEnd,
                    Children = child.Children
                };
                split.Children[child.Prefix[common]] = remainder;

                child.Prefix = word[i..];
                child.IsEnd = true;
                child.Children.Clear();
                split.Children[word[i + common]] = child;

                node.Children[c] = split;
                return;
            }
        }
        node.IsEnd = true;
    }

    private static int CommonPrefixLength(string a, string b)
    {
        int n = Math.Min(a.Length, b.Length);
        int i = 0;
        while (i < n && a[i] == b[i]) i++;
        return i;
    }

    public bool Contains(string word)
    {
        var node = _root;
        int i = 0;
        while (i < word.Length)
        {
            char c = word[i];
            if (!node.Children.TryGetValue(c, out var child)) return false;
            if (!word.AsSpan(i).StartsWith(child.Prefix)) return false;
            i += child.Prefix.Length;
            node = child;
        }
        return node.IsEnd;
    }
}

#endregion

#region Radix Tree

public sealed class RadixTree<TValue>
{
    private sealed class Node
    {
        public string Key = "";
        public TValue? Value;
        public bool HasValue;
        public Dictionary<char, Node> Children = new();
    }

    private readonly Node _root = new();

    public void Insert(string key, TValue value) => InsertRecursive(_root, key, value);

    private static void InsertRecursive(Node node, string key, TValue value)
    {
        if (key.Length == 0)
        {
            node.Value = value;
            node.HasValue = true;
            return;
        }

        char c = key[0];
        if (!node.Children.TryGetValue(c, out var child))
        {
            child = new Node { Key = key };
            node.Children[c] = child;
            child.Value = value;
            child.HasValue = true;
            return;
        }

        int common = CommonPrefix(child.Key, key);
        if (common == child.Key.Length)
        {
            InsertRecursive(child, key[common..], value);
            return;
        }

        var split = new Node { Key = child.Key[..common] };
        char splitChar = child.Key[common];
        child.Key = child.Key[(common + 1)..];
        split.Children[splitChar] = child;

        if (common == key.Length)
        {
            split.Value = value;
            split.HasValue = true;
        }
        else
        {
            char newChar = key[common];
            var leaf = new Node
            {
                Key = key[(common + 1)..],
                Value = value,
                HasValue = true
            };
            split.Children[newChar] = leaf;
        }

        node.Children[c] = split;
    }

    private static int CommonPrefix(string a, string b)
    {
        int n = Math.Min(a.Length, b.Length);
        int i = 0;
        while (i < n && a[i] == b[i]) i++;
        return i;
    }

    public bool TryGet(string key, out TValue? value)
    {
        var node = _root;
        int i = 0;
        while (i < key.Length)
        {
            if (!node.Children.TryGetValue(key[i], out var child))
            {
                value = default;
                return false;
            }

            if (!key.AsSpan(i).StartsWith(child.Key)) 
            {
                value = default;
                return false;
            }

            i += child.Key.Length;
            node = child;
        }
        value = node.Value;
        return node.HasValue;
    }
}

#endregion

#region Sweep Line

public static class SweepLine
{
    public readonly record struct Event(int X, int Type, int Y);

    public static int MaxOverlap(List<(int x1, int x2)> intervals)
    {
        var events = new List<(int x, int delta)>();
        foreach (var (x1, x2) in intervals)
        {
            events.Add((x1, 1));
            events.Add((x2, -1));
        }
        events.Sort((a, b) => a.x != b.x ? a.x.CompareTo(b.x) : a.delta.CompareTo(b.delta));

        int max = 0, current = 0;
        foreach (var (_, delta) in events)
        {
            current += delta;
            if (current > max) max = current;
        }
        return max;
    }

    public static double AreaOfUnionOfRectangles(List<(double x1, double y1, double x2, double y2)> rectangles)
    {
        var events = new List<(double x, int type, double y1, double y2)>();
        foreach (var (x1, y1, x2, y2) in rectangles)
        {
            events.Add((x1, 1, y1, y2));
            events.Add((x2, -1, y1, y2));
        }
        events.Sort((a, b) => a.x.CompareTo(b.x));

        double area = 0;
        double lastX = 0;
        var active = new List<(double y1, double y2)>();

        foreach (var (x, type, y1, y2) in events)
        {
            if (active.Count > 0)
                area += (x - lastX) * UnionLength(active);

            if (type == 1) active.Add((y1, y2));
            else active.Remove((y1, y2));

            lastX = x;
        }
        return area;
    }

    private static double UnionLength(List<(double y1, double y2)> intervals)
    {
        if (intervals.Count == 0) return 0;
        var sorted = intervals.OrderBy(i => i.y1).ToList();
        double total = 0;
        double start = sorted[0].y1;
        double end = sorted[0].y2;

        foreach (var (y1, y2) in sorted.Skip(1))
        {
            if (y1 > end)
            {
                total += end - start;
                start = y1;
                end = y2;
            }
            else
            {
                end = Math.Max(end, y2);
            }
        }
        total += end - start;
        return total;
    }
}

#endregion

#region Convex Hull

public static class ConvexHull
{
    public readonly record struct Point(double X, double Y);

    public static List<Point> Compute(List<Point> points)
    {
        if (points.Count < 3) return points;

        var sorted = points.OrderBy(p => p.X).ThenBy(p => p.Y).ToList();
        var hull = new List<Point>();

        foreach (var p in sorted)
        {
            while (hull.Count >= 2 && Cross(hull[^2], hull[^1], p) <= 0)
                hull.RemoveAt(hull.Count - 1);
            hull.Add(p);
        }

        int lower = hull.Count + 1;
        for (int i = sorted.Count - 2; i >= 0; i--)
        {
            var p = sorted[i];
            while (hull.Count >= lower && Cross(hull[^2], hull[^1], p) <= 0)
                hull.RemoveAt(hull.Count - 1);
            hull.Add(p);
        }

        hull.RemoveAt(hull.Count - 1);
        return hull;
    }

    private static double Cross(Point o, Point a, Point b)
        => (a.X - o.X) * (b.Y - o.Y) - (a.Y - o.Y) * (b.X - o.X);
}

#endregion

#region Closest Pair

public static class ClosestPair
{
    public readonly record struct Point(double X, double Y);

    public static (Point a, Point b, double distance) Find(List<Point> points)
    {
        var sorted = points.OrderBy(p => p.X).ToList();
        return Recursive(sorted);
    }

    private static (Point a, Point b, double distance) Recursive(List<Point> points)
    {
        if (points.Count <= 3) return BruteForce(points);

        int mid = points.Count / 2;
        var left = points.Take(mid).ToList();
        var right = points.Skip(mid).ToList();

        var dl = Recursive(left);
        var dr = Recursive(right);
        var d = dl.distance < dr.distance ? dl : dr;

        var strip = points.Where(p => Math.Abs(p.X - points[mid].X) < d.distance).ToList();
        strip = strip.OrderBy(p => p.Y).ToList();

        for (int i = 0; i < strip.Count; i++)
        {
            for (int j = i + 1; j < strip.Count && strip[j].Y - strip[i].Y < d.distance; j++)
            {
                double dist = Distance(strip[i], strip[j]);
                if (dist < d.distance) d = (strip[i], strip[j], dist);
            }
        }
        return d;
    }

    private static (Point a, Point b, double distance) BruteForce(List<Point> points)
    {
        var best = (points[0], points[1], Distance(points[0], points[1]));
        for (int i = 0; i < points.Count; i++)
            for (int j = i + 1; j < points.Count; j++)
            {
                double d = Distance(points[i], points[j]);
                if (d < best.Item3) best = (points[i], points[j], d);
            }
        return best;
    }

    private static double Distance(Point a, Point b)
    {
        double dx = a.X - b.X;
        double dy = a.Y - b.Y;
        return Math.Sqrt(dx * dx + dy * dy);
    }
}

#endregion

#region Line Intersection

public static class LineIntersection
{
    public readonly record struct Point(double X, double Y);

    public static Point? SegmentIntersection(Point p1, Point p2, Point p3, Point p4)
    {
        double d = (p2.X - p1.X) * (p4.Y - p3.Y) - (p2.Y - p1.Y) * (p4.X - p3.X);
        if (Math.Abs(d) < 1e-12) return null;

        double t = ((p3.X - p1.X) * (p4.Y - p3.Y) - (p3.Y - p1.Y) * (p4.X - p3.X)) / d;
        double s = ((p3.X - p1.X) * (p2.Y - p1.Y) - (p3.Y - p1.Y) * (p2.X - p1.X)) / d;

        if (t < 0 || t > 1 || s < 0 || s > 1) return null;

        return new Point(p1.X + t * (p2.X - p1.X), p1.Y + t * (p2.Y - p1.Y));
    }
}

#endregion

#region Delaunay Triangulation

public static class DelaunayTriangulation
{
    public readonly record struct Triangle(int A, int B, int C);

    public static List<Triangle> Compute(List<(double x, double y)> points)
    {
        int n = points.Count;
        if (n < 3) return new List<Triangle>();

        var triangulation = new List<Triangle>();

        for (int i = 0; i < n; i++)
        {
            for (int j = i + 1; j < n; j++)
            {
                for (int k = j + 1; k < n; k++)
                {
                    if (IsDelaunay(points, i, j, k))
                    {
                        triangulation.Add(new Triangle(i, j, k));
                    }
                }
            }
        }
        return triangulation;
    }

    private static bool IsDelaunay(List<(double x, double y)> points, int i, int j, int k)
    {
        var (cx, cy, r2) = Circumcircle(points[i], points[j], points[k]);

        for (int m = 0; m < points.Count; m++)
        {
            if (m == i || m == j || m == k) continue;
            double dx = points[m].x - cx;
            double dy = points[m].y - cy;
            if (dx * dx + dy * dy < r2 - 1e-10) return false;
        }
        return true;
    }

    private static (double cx, double cy, double r2) Circumcircle(
        (double x, double y) a, (double x, double y) b, (double x, double y) c)
    {
        double d = 2 * (a.x * (b.y - c.y) + b.x * (c.y - a.y) + c.x * (a.y - b.y));
        if (Math.Abs(d) < 1e-12) return (0, 0, double.MaxValue);

        double ux = ((a.x * a.x + a.y * a.y) * (b.y - c.y)
                   + (b.x * b.x + b.y * b.y) * (c.y - a.y)
                   + (c.x * c.x + c.y * c.y) * (a.y - b.y)) / d;

        double uy = ((a.x * a.x + a.y * a.y) * (c.x - b.x)
                   + (b.x * b.x + b.y * b.y) * (a.x - c.x)
                   + (c.x * c.x + c.y * c.y) * (b.x - a.x)) / d;

        double r2 = (a.x - ux) * (a.x - ux) + (a.y - uy) * (a.y - uy);
        return (ux, uy, r2);
    }
}

#endregion

#region Alpha Beta Pruning

public static class AlphaBeta
{
    public static int Search<TState>(TState state, int depth, int alpha, int beta,
        Func<TState, IEnumerable<TState>> getChildren,
        Func<TState, int> evaluate,
        Func<TState, bool> isTerminal,
        bool maximizing)
    {
        if (depth == 0 || isTerminal(state))
            return evaluate(state);

        if (maximizing)
        {
            int value = int.MinValue;
            foreach (var child in getChildren(state))
            {
                value = Math.Max(value, Search(child, depth - 1, alpha, beta, getChildren, evaluate, isTerminal, false));
                if (value >= beta) break;
                alpha = Math.Max(alpha, value);
            }
            return value;
        }
        else
        {
            int value = int.MaxValue;
            foreach (var child in getChildren(state))
            {
                value = Math.Min(value, Search(child, depth - 1, alpha, beta, getChildren, evaluate, isTerminal, true));
                if (value <= alpha) break;
                beta = Math.Min(beta, value);
            }
            return value;
        }
    }
}

#endregion

#region Monte Carlo Tree Search

public sealed class MctsNode<TState, TAction>
{
    public TState State { get; }
    public TAction? Action { get; }
    public MctsNode<TState, TAction>? Parent { get; }
    public List<MctsNode<TState, TAction>> Children { get; } = new();
    public double Wins { get; set; }
    public int Visits { get; set; }
    public List<TAction> UntriedActions { get; set; }

    public MctsNode(TState state, TAction? action, MctsNode<TState, TAction>? parent, List<TAction> untriedActions)
    {
        State = state;
        Action = action;
        Parent = parent;
        UntriedActions = untriedActions;
    }

    public bool IsFullyExpanded => UntriedActions.Count == 0;
    public bool IsLeaf => Children.Count == 0;

    public double Ucb1(double c = 1.414)
    {
        if (Visits == 0) return double.MaxValue;
        return Wins / Visits + c * Math.Sqrt(Math.Log(Parent?.Visits ?? 1) / Visits);
    }
}

public sealed class Mcts<TState, TAction>
{
    private readonly Func<TState, List<TAction>> _getActions;
    private readonly Func<TState, TAction, TState> _applyAction;
    private readonly Func<TState> _getInitialState;
    private readonly Func<TState, bool> _isTerminal;
    private readonly Func<TState, double> _simulate;
    private readonly Random _random = new();

    public Mcts(
        Func<TState> getInitialState,
        Func<TState, List<TAction>> getActions,
        Func<TState, TAction, TState> applyAction,
        Func<TState, bool> isTerminal,
        Func<TState, double> simulate)
    {
        _getInitialState = getInitialState;
        _getActions = getActions;
        _applyAction = applyAction;
        _isTerminal = isTerminal;
        _simulate = simulate;
    }

    public TAction? Search(int iterations)
    {
        var root = new MctsNode<TState, TAction>(_getInitialState(), default, null, _getActions(_getInitialState()));

        for (int i = 0; i < iterations; i++)
        {
            var node = Select(root);
            node = Expand(node);
            double result = _simulate(node.State);
            Backpropagate(node, result);
        }

        return root.Children.OrderByDescending(c => c.Visits).FirstOrDefault()?.Action;
    }

    private MctsNode<TState, TAction> Select(MctsNode<TState, TAction> node)
    {
        while (!_isTerminal(node.State) && node.IsFullyExpanded && !node.IsLeaf)
        {
            node = node.Children.OrderByDescending(c => c.Ucb1()).First();
        }
        return node;
    }

    private MctsNode<TState, TAction> Expand(MctsNode<TState, TAction> node)
    {
        if (_isTerminal(node.State) || node.UntriedActions.Count == 0) return node;

        int idx = _random.Next(node.UntriedActions.Count);
        var action = node.UntriedActions[idx];
        node.UntriedActions.RemoveAt(idx);

        var newState = _applyAction(node.State, action);
        var child = new MctsNode<TState, TAction>(newState, action, node, _getActions(newState));
        node.Children.Add(child);
        return child;
    }

    private static void Backpropagate(MctsNode<TState, TAction> node, double result)
    {
        while (node != null)
        {
            node.Visits++;
            node.Wins += result;
            node = node.Parent!;
        }
    }
}

#endregion

#region Simulated Annealing

public static class SimulatedAnnealing
{
    public static T Optimize<T>(
        T initial,
        Func<T, double> energy,
        Func<T, Random, T> neighbor,
        double temperature = 1000.0,
        double coolingRate = 0.003,
        int maxIterations = 100000,
        int? seed = null)
    {
        var random = seed.HasValue ? new Random(seed.Value) : new Random();
        T current = initial;
        T best = initial;
        double currentEnergy = energy(current);
        double bestEnergy = currentEnergy;

        for (int i = 0; i < maxIterations && temperature > 0.01; i++)
        {
            T candidate = neighbor(current, random);
            double candidateEnergy = energy(candidate);
            double delta = candidateEnergy - currentEnergy;

            if (delta < 0 || random.NextDouble() < Math.Exp(-delta / temperature))
            {
                current = candidate;
                currentEnergy = candidateEnergy;

                if (currentEnergy < bestEnergy)
                {
                    best = current;
                    bestEnergy = currentEnergy;
                }
            }
            temperature *= 1 - coolingRate;
        }
        return best;
    }
}

#endregion

#region Genetic Algorithm

public static class GeneticAlgorithm
{
    public static T[] Evolve<T>(
        int populationSize,
        int genomeLength,
        Func<Random, T> randomGene,
        Func<T[], double> fitness,
        Func<T[], T[], Random, T[]> crossover,
        Action<T[], Random> mutate,
        int generations = 100,
        double eliteFraction = 0.1,
        int? seed = null)
    {
        var random = seed.HasValue ? new Random(seed.Value) : new Random();
        var population = new List<T[]>();

        for (int i = 0; i < populationSize; i++)
        {
            var genome = new T[genomeLength];
            for (int j = 0; j < genomeLength; j++) genome[j] = randomGene(random);
            population.Add(genome);
        }

        int eliteCount = Math.Max(1, (int)(populationSize * eliteFraction));

        for (int gen = 0; gen < generations; gen++)
        {
            var scored = population
                .Select(g => (genome: g, score: fitness(g)))
                .OrderByDescending(x => x.score)
                .ToList();

            var nextGeneration = new List<T[]>();
            for (int i = 0; i < eliteCount; i++)
                nextGeneration.Add(scored[i].genome);

            while (nextGeneration.Count < populationSize)
            {
                var parent1 = Tournament(scored, random);
                var parent2 = Tournament(scored, random);
                var child = crossover(parent1, parent2, random);
                mutate(child, random);
                nextGeneration.Add(child);
            }
            population = nextGeneration;
        }

        return population.OrderByDescending(g => fitness(g)).First();
    }

    private static T[] Tournament<T>(List<(T[] genome, double score)> population, Random random, int size = 3)
    {
        T[] best = population[random.Next(population.Count)].genome;
        double bestScore = population.First(x => x.genome == best).score;

        for (int i = 1; i < size; i++)
        {
            var candidate = population[random.Next(population.Count)];
            if (candidate.score > bestScore)
            {
                best = candidate.genome;
                bestScore = candidate.score;
            }
        }
        return best;
    }
}

#endregion

#region Particle Swarm Optimization

public static class ParticleSwarm
{
    public sealed class Particle
    {
        public double[] Position = Array.Empty<double>();
        public double[] Velocity = Array.Empty<double>();
        public double[] BestPosition = Array.Empty<double>();
        public double BestFitness = double.MaxValue;
    }

    public static double[] Optimize(
        Func<double[], double> objective,
        int dimensions,
        int swarmSize = 30,
        int iterations = 100,
        double inertia = 0.7,
        double cognitive = 1.5,
        double social = 1.5,
        double[]? lowerBounds = null,
        double[]? upperBounds = null,
        int? seed = null)
    {
        var random = seed.HasValue ? new Random(seed.Value) : new Random();
        var lo = lowerBounds ?? Enumerable.Repeat(-100.0, dimensions).ToArray();
        var hi = upperBounds ?? Enumerable.Repeat(100.0, dimensions).ToArray();

        var particles = new Particle[swarmSize];
        double[] globalBest = new double[dimensions];
        double globalBestFitness = double.MaxValue;

        for (int i = 0; i < swarmSize; i++)
        {
            var position = new double[dimensions];
            var velocity = new double[dimensions];
            for (int d = 0; d < dimensions; d++)
            {
                position[d] = lo[d] + random.NextDouble() * (hi[d] - lo[d]);
                velocity[d] = (random.NextDouble() - 0.5) * (hi[d] - lo[d]) * 0.1;
            }

            var p = new Particle
            {
                Position = position,
                Velocity = velocity,
                BestPosition = (double[])position.Clone()
            };
            p.BestFitness = objective(position);
            if (p.BestFitness < globalBestFitness)
            {
                globalBestFitness = p.BestFitness;
                globalBest = (double[])position.Clone();
            }
            particles[i] = p;
        }

        for (int iter = 0; iter < iterations; iter++)
        {
            foreach (var p in particles)
            {
                for (int d = 0; d < dimensions; d++)
                {
                    double r1 = random.NextDouble();
                    double r2 = random.NextDouble();
                    p.Velocity[d] = inertia * p.Velocity[d]
                        + cognitive * r1 * (p.BestPosition[d] - p.Position[d])
                        + social * r2 * (globalBest[d] - p.Position[d]);
                    p.Position[d] += p.Velocity[d];
                    p.Position[d] = Math.Max(lo[d], Math.Min(hi[d], p.Position[d]));
                }

                double fitness = objective(p.Position);
                if (fitness < p.BestFitness)
                {
                    p.BestFitness = fitness;
                    p.BestPosition = (double[])p.Position.Clone();

                    if (fitness < globalBestFitness)
                    {
                        globalBestFitness = fitness;
                        globalBest = (double[])p.Position.Clone();
                    }
                }
            }
        }
        return globalBest;
    }
}

#endregion

#region Ant Colony Optimization

public static class AntColony
{
    public static (int[] path, double distance) SolveTsp(double[,] distances, int antCount = 20, int iterations = 100,
        double alpha = 1.0, double beta = 2.0, double evaporation = 0.5, double q = 100.0, int? seed = null)
    {
        var random = seed.HasValue ? new Random(seed.Value) : new Random();
        int n = distances.GetLength(0);
        double[,] pheromone = new double[n, n];

        for (int i = 0; i < n; i++)
            for (int j = 0; j < n; j++)
                pheromone[i, j] = 1.0;

        int[] bestPath = new int[n];
        double bestDistance = double.MaxValue;

        for (int iter = 0; iter < iterations; iter++)
        {
            var antPaths = new List<(int[] path, double distance)>();

            for (int ant = 0; ant < antCount; ant++)
            {
                var path = new int[n];
                var visited = new bool[n];
                int current = random.Next(n);
                path[0] = current;
                visited[current] = true;

                for (int step = 1; step < n; step++)
                {
                    double totalProb = 0;
                    var probabilities = new double[n];

                    for (int j = 0; j < n; j++)
                    {
                        if (visited[j]) continue;
                        double prob = Math.Pow(pheromone[current, j], alpha)
                                    * Math.Pow(1.0 / Math.Max(distances[current, j], 1e-12), beta);
                        probabilities[j] = prob;
                        totalProb += prob;
                    }

                    double r = random.NextDouble() * totalProb;
                    double cumulative = 0;
                    int next = -1;

                    for (int j = 0; j < n; j++)
                    {
                        if (visited[j]) continue;
                        cumulative += probabilities[j];
                        if (cumulative >= r)
                        {
                            next = j;
                            break;
                        }
                    }

                    if (next < 0)
                    {
                        for (int j = 0; j < n; j++)
                            if (!visited[j]) { next = j; break; }
                    }

                    path[step] = next;
                    visited[next] = true;
                    current = next;
                }

                double distance = 0;
                for (int i = 0; i < n; i++)
                    distance += distances[path[i], path[(i + 1) % n]];

                antPaths.Add((path, distance));

                if (distance < bestDistance)
                {
                    bestDistance = distance;
                    bestPath = (int[])path.Clone();
                }
            }

            for (int i = 0; i < n; i++)
                for (int j = 0; j < n; j++)
                    pheromone[i, j] *= 1 - evaporation;

            foreach (var (path, distance) in antPaths)
            {
                double deposit = q / distance;
                for (int i = 0; i < n; i++)
                {
                    int from = path[i];
                    int to = path[(i + 1) % n];
                    pheromone[from, to] += deposit;
                    pheromone[to, from] += deposit;
                }
            }
        }

        return (bestPath, bestDistance);
    }
}

#endregion

#region K-Means Clustering

public static class KMeans
{
    public static (double[][] centroids, int[] labels) Cluster(double[][] data, int k, int maxIterations = 100, int? seed = null)
    {
        var random = seed.HasValue ? new Random(seed.Value) : new Random();
        int n = data.Length;
        int d = data[0].Length;

        var centroids = new double[k][];
        var usedIndices = new HashSet<int>();
        for (int i = 0; i < k; i++)
        {
            int idx;
            do { idx = random.Next(n); } while (usedIndices.Contains(idx) && usedIndices.Count < n);
            usedIndices.Add(idx);
            centroids[i] = (double[])data[idx].Clone();
        }

        var labels = new int[n];
        for (int iter = 0; iter < maxIterations; iter++)
        {
            bool changed = false;

            for (int i = 0; i < n; i++)
            {
                int bestCluster = 0;
                double bestDist = double.MaxValue;

                for (int c = 0; c < k; c++)
                {
                    double dist = 0;
                    for (int j = 0; j < d; j++)
                    {
                        double diff = data[i][j] - centroids[c][j];
                        dist += diff * diff;
                    }
                    if (dist < bestDist)
                    {
                        bestDist = dist;
                        bestCluster = c;
                    }
                }

                if (labels[i] != bestCluster)
                {
                    labels[i] = bestCluster;
                    changed = true;
                }
            }

            if (!changed) break;

            for (int c = 0; c < k; c++)
            {
                var sums = new double[d];
                int count = 0;
                for (int i = 0; i < n; i++)
                {
                    if (labels[i] != c) continue;
                    for (int j = 0; j < d; j++) sums[j] += data[i][j];
                    count++;
                }
                if (count > 0)
                    for (int j = 0; j < d; j++) centroids[c][j] = sums[j] / count;
            }
        }

        return (centroids, labels);
    }

    public static double Inertia(double[][] data, double[][] centroids, int[] labels)
    {
        double inertia = 0;
        for (int i = 0; i < data.Length; i++)
        {
            for (int j = 0; j < data[i].Length; j++)
            {
                double diff = data[i][j] - centroids[labels[i]][j];
                inertia += diff * diff;
            }
        }
        return inertia;
    }
}

#endregion

#region DBSCAN

public static class Dbscan
{
    public static int[] Cluster(double[][] points, double epsilon, int minPts)
    {
        int n = points.Length;
        int[] labels = new int[n];
        Array.Fill(labels, -1);
        int clusterId = 0;

        for (int i = 0; i < n; i++)
        {
            if (labels[i] != -1) continue;

            var neighbors = GetNeighbors(points, i, epsilon);
            if (neighbors.Count < minPts)
            {
                labels[i] = 0;
                continue;
            }

            clusterId++;
            labels[i] = clusterId;

            var queue = new Queue<int>(neighbors);
            while (queue.Count > 0)
            {
                int current = queue.Dequeue();

                if (labels[current] == 0) labels[current] = clusterId;
                if (labels[current] != -1) continue;

                labels[current] = clusterId;
                var currentNeighbors = GetNeighbors(points, current, epsilon);
                if (currentNeighbors.Count >= minPts)
                {
                    foreach (int neighbor in currentNeighbors)
                        if (labels[neighbor] == -1 || labels[neighbor] == 0)
                            queue.Enqueue(neighbor);
                }
            }
        }
        return labels;
    }

    private static List<int> GetNeighbors(double[][] points, int index, double epsilon)
    {
        var neighbors = new List<int>();
        double eps2 = epsilon * epsilon;
        for (int i = 0; i < points.Length; i++)
        {
            if (i == index) continue;
            double dist = 0;
            for (int j = 0; j < points[index].Length; j++)
            {
                double diff = points[index][j] - points[i][j];
                dist += diff * diff;
            }
            if (dist <= eps2) neighbors.Add(i);
        }
        return neighbors;
    }
}

#endregion

#region PCA

public static class PrincipalComponentAnalysis
{
    public static (double[][] components, double[] explainedVariance) Compute(double[][] data, int numComponents)
    {
        int n = data.Length;
        int d = data[0].Length;

        var means = new double[d];
        for (int i = 0; i < n; i++)
            for (int j = 0; j < d; j++)
                means[j] += data[i][j];
        for (int j = 0; j < d; j++) means[j] /= n;

        var centered = new double[n][];
        for (int i = 0; i < n; i++)
        {
            centered[i] = new double[d];
            for (int j = 0; j < d; j++)
                centered[i][j] = data[i][j] - means[j];
        }

        var covariance = new double[d, d];
        for (int i = 0; i < d; i++)
        {
            for (int j = i; j < d; j++)
            {
                double sum = 0;
                for (int k = 0; k < n; k++)
                    sum += centered[k][i] * centered[k][j];
                covariance[i, j] = sum / (n - 1);
                covariance[j, i] = covariance[i, j];
            }
        }

        var (eigenvalues, eigenvectors) = PowerIteration(covariance, numComponents);

        var totalVariance = 0.0;
        for (int i = 0; i < d; i++) totalVariance += covariance[i, i];

        var explained = new double[numComponents];
        for (int i = 0; i < numComponents; i++)
            explained[i] = eigenvalues[i] / totalVariance;

        return (eigenvectors, explained);
    }

    private static (double[] eigenvalues, double[][] eigenvectors) PowerIteration(double[,] matrix, int k)
    {
        int n = matrix.GetLength(0);
        var eigenvalues = new double[k];
        var eigenvectors = new double[k][];

        var residual = (double[,])matrix.Clone();

        for (int comp = 0; comp < k; comp++)
        {
            var v = new double[n];
            var random = new Random(42 + comp);
            for (int i = 0; i < n; i++) v[i] = random.NextDouble() - 0.5;

            for (int iter = 0; iter < 1000; iter++)
            {
                var next = new double[n];
                for (int i = 0; i < n; i++)
                    for (int j = 0; j < n; j++)
                        next[i] += residual[i, j] * v[j];

                double norm = 0;
                for (int i = 0; i < n; i++) norm += next[i] * next[i];
                norm = Math.Sqrt(norm);
                if (norm < 1e-12) break;

                for (int i = 0; i < n; i++) next[i] /= norm;
                v = next;
            }

            var av = new double[n];
            for (int i = 0; i < n; i++)
                for (int j = 0; j < n; j++)
                    av[i] += residual[i, j] * v[j];

            double lambda = 0;
            for (int i = 0; i < n; i++) lambda += v[i] * av[i];

            eigenvalues[comp] = lambda;
            eigenvectors[comp] = v;

            for (int i = 0; i < n; i++)
                for (int j = 0; j < n; j++)
                    residual[i, j] -= lambda * v[i] * v[j];
        }

        return (eigenvalues, eigenvectors);
    }
}

#endregion

#region Fast ICA

public static class FastIca
{
    public static double[][] Decompose(double[][] data, int components, int maxIterations = 200, double tolerance = 1e-6)
    {
        int n = data.Length;
        int d = data[0].Length;

        var centered = Center(data);
        var whitened = Whiten(centered, d);

        var weights = new double[components][];
        var random = new Random(42);

        for (int i = 0; i < components; i++)
        {
            var w = new double[d];
            for (int j = 0; j < d; j++) w[j] = random.NextDouble() - 0.5;

            for (int iter = 0; iter < maxIterations; iter++)
            {
                var wx = new double[n];
                for (int k = 0; k < n; k++)
                    for (int j = 0; j < d; j++)
                        wx[k] += w[j] * whitened[k][j];

                var gwx = new double[n];
                var gPrimewx = new double[n];
                for (int k = 0; k < n; k++)
                {
                    gwx[k] = Math.Tanh(wx[k]);
                    gPrimewx[k] = 1 - gwx[k] * gwx[k];
                }

                var wNew = new double[d];
                for (int j = 0; j < d; j++)
                {
                    double sum = 0;
                    for (int k = 0; k < n; k++)
                        sum += whitened[k][j] * gwx[k];
                    wNew[j] = sum / n;
                }

                double meanGPrime = 0;
                for (int k = 0; k < n; k++) meanGPrime += gPrimewx[k];
                meanGPrime /= n;

                for (int j = 0; j < d; j++)
                    wNew[j] -= meanGPrime * w[j];

                double norm = 0;
                for (int j = 0; j < d; j++) norm += wNew[j] * wNew[j];
                norm = Math.Sqrt(norm);
                for (int j = 0; j < d; j++) wNew[j] /= norm;

                double dot = 0;
                for (int j = 0; j < d; j++) dot += wNew[j] * w[j];
                if (Math.Abs(Math.Abs(dot) - 1) < tolerance)
                {
                    w = wNew;
                    break;
                }
                w = wNew;
            }

            for (int prev = 0; prev < i; prev++)
            {
                double dot = 0;
                for (int j = 0; j < d; j++) dot += w[j] * weights[prev][j];
                for (int j = 0; j < d; j++) w[j] -= dot * weights[prev][j];
            }

            double renorm = 0;
            for (int j = 0; j < d; j++) renorm += w[j] * w[j];
            renorm = Math.Sqrt(renorm);
            for (int j = 0; j < d; j++) w[j] /= renorm;

            weights[i] = w;
        }

        return weights;
    }

    private static double[][] Center(double[][] data)
    {
        int n = data.Length;
        int d = data[0].Length;
        var means = new double[d];
        for (int i = 0; i < n; i++)
            for (int j = 0; j < d; j++)
                means[j] += data[i][j];
        for (int j = 0; j < d; j++) means[j] /= n;

        var result = new double[n][];
        for (int i = 0; i < n; i++)
        {
            result[i] = new double[d];
            for (int j = 0; j < d; j++)
                result[i][j] = data[i][j] - means[j];
        }
        return result;
    }

    private static double[][] Whiten(double[][] data, int d)
    {
        int n = data.Length;
        var cov = new double[d, d];
        for (int i = 0; i < d; i++)
            for (int j = 0; j < d; j++)
                for (int k = 0; k < n; k++)
                    cov[i, j] += data[k][i] * data[k][j];
        for (int i = 0; i < d; i++)
            for (int j = 0; j < d; j++)
                cov[i, j] /= n;

        var whitened = new double[n][];
        for (int i = 0; i < n; i++)
        {
            whitened[i] = new double[d];
            for (int j = 0; j < d; j++)
                whitened[i][j] = data[i][j];
        }
        return whitened;
    }
}

#endregion

#region Markov Chain

public sealed class MarkovChain<TState> where TState : notnull
{
    private readonly Dictionary<TState, Dictionary<TState, int>> _transitions = new();
    private readonly Dictionary<TState, int> _totals = new();

    public void Train(IEnumerable<TState> sequence)
    {
        var previous = default(TState);
        bool hasPrevious = false;

        foreach (var state in sequence)
        {
            if (hasPrevious && previous is not null)
            {
                if (!_transitions.TryGetValue(previous, out var counts))
                {
                    counts = new Dictionary<TState, int>();
                    _transitions[previous] = counts;
                }
                counts.TryGetValue(state, out int existing);
                counts[state] = existing + 1;
                _totals.TryGetValue(previous, out int total);
                _totals[previous] = total + 1;
            }
            previous = state;
            hasPrevious = true;
        }
    }

    public IEnumerable<TState> Generate(TState start, int length, Random? random = null)
    {
        var rng = random ?? new Random();
        var current = start;
        for (int i = 0; i < length; i++)
        {
            yield return current;

            if (!_transitions.TryGetValue(current, out var counts) || counts.Count == 0)
                yield break;

            int total = _totals[current];
            int roll = rng.Next(total);
            int cumulative = 0;

            foreach (var kv in counts)
            {
                cumulative += kv.Value;
                if (roll < cumulative)
                {
                    current = kv.Key;
                    break;
                }
            }
        }
    }

    public double TransitionProbability(TState from, TState to)
    {
        if (!_transitions.TryGetValue(from, out var counts)) return 0;
        if (!counts.TryGetValue(to, out int count)) return 0;
        return (double)count / _totals[from];
    }
}

#endregion

#region Hidden Markov Model

public sealed class HiddenMarkovModel<TState, TObservation>
    where TState : notnull
    where TObservation : notnull
{
    public Dictionary<TState, double> InitialProbabilities { get; set; } = new();
    public Dictionary<TState, Dictionary<TState, double>> TransitionProbabilities { get; set; } = new();
    public Dictionary<TState, Dictionary<TObservation, double>> EmissionProbabilities { get; set; } = new();

    public List<TState> Viterbi(IReadOnlyList<TObservation> observations)
    {
        var states = InitialProbabilities.Keys.ToList();
        int n = observations.Count;

        var delta = new double[n, states.Count];
        var psi = new int[n, states.Count];
        var stateIndex = states.Select((s, i) => (s, i)).ToDictionary(x => x.s, x => x.i);

        for (int i = 0; i < states.Count; i++)
        {
            var state = states[i];
            double emission = GetEmission(state, observations[0]);
            delta[0, i] = Math.Log(InitialProbabilities.GetValueOrDefault(state, 1e-10)) + Math.Log(Math.Max(emission, 1e-10));
            psi[0, i] = -1;
        }

        for (int t = 1; t < n; t++)
        {
            for (int i = 0; i < states.Count; i++)
            {
                var currentState = states[i];
                double maxProb = double.NegativeInfinity;
                int bestPrev = 0;

                for (int j = 0; j < states.Count; j++)
                {
                    var prevState = states[j];
                    double trans = GetTransition(prevState, currentState);
                    double prob = delta[t - 1, j] + Math.Log(Math.Max(trans, 1e-10));

                    if (prob > maxProb)
                    {
                        maxProb = prob;
                        bestPrev = j;
                    }
                }

                double emission = GetEmission(currentState, observations[t]);
                delta[t, i] = maxProb + Math.Log(Math.Max(emission, 1e-10));
                psi[t, i] = bestPrev;
            }
        }

        int lastBest = 0;
        double lastMax = double.NegativeInfinity;
        for (int i = 0; i < states.Count; i++)
        {
            if (delta[n - 1, i] > lastMax)
            {
                lastMax = delta[n - 1, i];
                lastBest = i;
            }
        }

        var path = new List<TState> { states[lastBest] };
        for (int t = n - 1; t > 0; t--)
        {
            lastBest = psi[t, lastBest];
            path.Insert(0, states[lastBest]);
        }
        return path;
    }

    private double GetTransition(TState from, TState to)
    {
        if (TransitionProbabilities.TryGetValue(from, out var row))
            return row.GetValueOrDefault(to, 1e-10);
        return 1e-10;
    }

    private double GetEmission(TState state, TObservation observation)
    {
        if (EmissionProbabilities.TryGetValue(state, out var row))
            return row.GetValueOrDefault(observation, 1e-10);
        return 1e-10;
    }
}

#endregion

#region Edit Script

public static class EditScript
{
    public enum OperationType { Insert, Delete, Replace, Equal }

    public readonly record struct Operation(OperationType Type, int OldIndex, int NewIndex, string? Value);

    public static List<Operation> Compute(string[] oldSequence, string[] newSequence)
    {
        int n = oldSequence.Length;
        int m = newSequence.Length;
        var dp = new int[n + 1, m + 1];

        for (int i = 0; i <= n; i++) dp[i, 0] = i;
        for (int j = 0; j <= m; j++) dp[0, j] = j;

        for (int i = 1; i <= n; i++)
        {
            for (int j = 1; j <= m; j++)
            {
                if (oldSequence[i - 1] == newSequence[j - 1])
                    dp[i, j] = dp[i - 1, j - 1];
                else
                    dp[i, j] = 1 + Math.Min(Math.Min(dp[i - 1, j], dp[i, j - 1]), dp[i - 1, j - 1]);
            }
        }

        var operations = new List<Operation>();
        int x = n, y = m;
        while (x > 0 || y > 0)
        {
            if (x > 0 && y > 0 && oldSequence[x - 1] == newSequence[y - 1])
            {
                operations.Insert(0, new Operation(OperationType.Equal, x - 1, y - 1, oldSequence[x - 1]));
                x--;
                y--;
            }
            else if (x > 0 && y > 0 && dp[x, y] == dp[x - 1, y - 1] + 1)
            {
                operations.Insert(0, new Operation(OperationType.Replace, x - 1, y - 1, newSequence[y - 1]));
                x--;
                y--;
            }
            else if (x > 0 && dp[x, y] == dp[x - 1, y] + 1)
            {
                operations.Insert(0, new Operation(OperationType.Delete, x - 1, -1, null));
                x--;
            }
            else
            {
                operations.Insert(0, new Operation(OperationType.Insert, -1, y - 1, newSequence[y - 1]));
                y--;
            }
        }
        return operations;
    }
}

#endregion

#region Longest Increasing Subsequence

public static class Lis
{
    public static int Length<T>(ReadOnlySpan<T> data) where T : IComparable<T>
    {
        if (data.Length == 0) return 0;
        var tails = new List<T>();
        foreach (var value in data)
        {
            int lo = 0, hi = tails.Count;
            while (lo < hi)
            {
                int mid = (lo + hi) / 2;
                if (tails[mid].CompareTo(value) < 0) lo = mid + 1;
                else hi = mid;
            }
            if (lo == tails.Count) tails.Add(value);
            else tails[lo] = value;
        }
        return tails.Count;
    }

    public static List<T> Recover<T>(ReadOnlySpan<T> data) where T : IComparable<T>
    {
        int n = data.Length;
        if (n == 0) return new List<T>();

        var tails = new List<int>();
        var prev = new int[n];
        Array.Fill(prev, -1);

        for (int i = 0; i < n; i++)
        {
            int lo = 0, hi = tails.Count;
            while (lo < hi)
            {
                int mid = (lo + hi) / 2;
                if (data[tails[mid]].CompareTo(data[i]) < 0) lo = mid + 1;
                else hi = mid;
            }
            if (lo > 0) prev[i] = tails[lo - 1];
            if (lo == tails.Count) tails.Add(i);
            else tails[lo] = i;
        }

        var result = new List<T>();
        int current = tails[^1];
        while (current >= 0)
        {
            result.Add(data[current]);
            current = prev[current];
        }
        result.Reverse();
        return result;
    }
}

#endregion

#region Longest Palindromic Subsequence

public static class Lps
{
    public static int Length(ReadOnlySpan<char> s)
    {
        int n = s.Length;
        if (n == 0) return 0;
        int[,] dp = new int[n, n];
        for (int i = 0; i < n; i++) dp[i, i] = 1;
        for (int len = 2; len <= n; len++)
        {
            for (int i = 0; i < n - len + 1; i++)
            {
                int j = i + len - 1;
                if (s[i] == s[j] && len == 2) dp[i, j] = 2;
                else if (s[i] == s[j]) dp[i, j] = dp[i + 1, j - 1] + 2;
                else dp[i, j] = Math.Max(dp[i + 1, j], dp[i, j - 1]);
            }
        }
        return dp[0, n - 1];
    }
}

#endregion

#region Minimum Coin Change

public static class CoinChange
{
    public static int MinCoins(int[] coins, int amount)
    {
        int[] dp = new int[amount + 1];
        Array.Fill(dp, int.MaxValue);
        dp[0] = 0;

        for (int i = 1; i <= amount; i++)
        {
            foreach (int coin in coins)
            {
                if (coin <= i && dp[i - coin] != int.MaxValue)
                {
                    dp[i] = Math.Min(dp[i], dp[i - coin] + 1);
                }
            }
        }
        return dp[amount] == int.MaxValue ? -1 : dp[amount];
    }

    public static int CountWays(int[] coins, int amount)
    {
        int[] dp = new int[amount + 1];
        dp[0] = 1;
        foreach (int coin in coins)
        {
            for (int i = coin; i <= amount; i++)
            {
                dp[i] += dp[i - coin];
            }
        }
        return dp[amount];
    }
}

#endregion

#region Longest Common Substring

public static class LcSubstring
{
    public static string Find(ReadOnlySpan<char> a, ReadOnlySpan<char> b)
    {
        int n = a.Length, m = b.Length;
        int[,] dp = new int[n + 1, m + 1];
        int maxLen = 0, endIndex = 0;

        for (int i = 1; i <= n; i++)
        {
            for (int j = 1; j <= m; j++)
            {
                if (a[i - 1] == b[j - 1])
                {
                    dp[i, j] = dp[i - 1, j - 1] + 1;
                    if (dp[i, j] > maxLen)
                    {
                        maxLen = dp[i, j];
                        endIndex = i - 1;
                    }
                }
            }
        }
        return maxLen == 0 ? "" : a.Slice(endIndex - maxLen + 1, maxLen).ToString();
    }
}

#endregion

#region Damerau Levenshtein Optimal String Alignment

public static class Osa
{
    public static int Distance(ReadOnlySpan<char> a, ReadOnlySpan<char> b)
    {
        int n = a.Length, m = b.Length;
        int[,] dp = new int[n + 1, m + 1];
        for (int i = 0; i <= n; i++) dp[i, 0] = i;
        for (int j = 0; j <= m; j++) dp[0, j] = j;

        for (int i = 1; i <= n; i++)
        {
            for (int j = 1; j <= m; j++)
            {
                int cost = a[i - 1] == b[j - 1] ? 0 : 1;
                dp[i, j] = Math.Min(Math.Min(dp[i - 1, j] + 1, dp[i, j - 1] + 1), dp[i - 1, j - 1] + cost);

                if (i > 1 && j > 1 && a[i - 1] == b[j - 2] && a[i - 2] == b[j - 1])
                {
                    dp[i, j] = Math.Min(dp[i, j], dp[i - 2, j - 2] + 1);
                }
            }
        }
        return dp[n, m];
    }
}

#endregion

#region Approximate String Search

public static class ApproximateStringSearch
{
    public static List<(int position, int distance)> Search(string text, string pattern, int maxDistance)
    {
        var results = new List<(int, int)>();
        int n = text.Length;
        int m = pattern.Length;

        for (int start = 0; start <= n - m + maxDistance; start++)
        {
            int best = int.MaxValue;

            for (int end = Math.Max(start + 1, start + m - maxDistance); end <= Math.Min(n, start + m + maxDistance); end++)
            {
                int dist = Levenshtein(text.AsSpan(start, end - start), pattern.AsSpan());
                best = Math.Min(best, dist);
            }

            if (best <= maxDistance)
                results.Add((start, best));
        }
        return results;
    }

    private static int Levenshtein(ReadOnlySpan<char> a, ReadOnlySpan<char> b)
    {
        int n = a.Length, m = b.Length;
        int[,] dp = new int[n + 1, m + 1];
        for (int i = 0; i <= n; i++) dp[i, 0] = i;
        for (int j = 0; j <= m; j++) dp[0, j] = j;

        for (int i = 1; i <= n; i++)
        {
            for (int j = 1; j <= m; j++)
            {
                int cost = a[i - 1] == b[j - 1] ? 0 : 1;
                dp[i, j] = Math.Min(Math.Min(dp[i - 1, j] + 1, dp[i, j - 1] + 1), dp[i - 1, j - 1] + cost);
            }
        }
        return dp[n, m];
    }
}

#endregion

#region Bit Array

public sealed class BitArrayWrapper
{
    private readonly ulong[] _words;
    private readonly int _length;

    public BitArrayWrapper(int length)
    {
        _length = length;
        _words = new ulong[(length + 63) / 64];
    }

    public int Length => _length;

    public bool this[int index]
    {
        get => (_words[index >> 6] & (1UL << (index & 63))) != 0;
        set
        {
            if (value) _words[index >> 6] |= 1UL << (index & 63);
            else _words[index >> 6] &= ~(1UL << (index & 63));
        }
    }

    public int PopCount()
    {
        int total = 0;
        foreach (ulong w in _words) total += BitMath.PopCount(w);
        return total;
    }

    public void SetAll(bool value)
    {
        ulong fill = value ? ulong.MaxValue : 0;
        for (int i = 0; i < _words.Length; i++) _words[i] = fill;
        if (value && (_length & 63) != 0)
        {
            int lastBits = _length & 63;
            _words[^1] = (1UL << lastBits) - 1;
        }
    }

    public void And(BitArrayWrapper other)
    {
        for (int i = 0; i < _words.Length; i++) _words[i] &= other._words[i];
    }

    public void Or(BitArrayWrapper other)
    {
        for (int i = 0; i < _words.Length; i++) _words[i] |= other._words[i];
    }

    public void Xor(BitArrayWrapper other)
    {
        for (int i = 0; i < _words.Length; i++) _words[i] ^= other._words[i];
    }

    public void Not()
    {
        for (int i = 0; i < _words.Length; i++) _words[i] = ~_words[i];
        if ((_length & 63) != 0)
        {
            int lastBits = _length & 63;
            _words[^1] &= (1UL << lastBits) - 1;
        }
    }
}

#endregion

#region Interval Tree

public sealed class IntervalTree
{
    public readonly record struct Interval(long Start, long End);

    private sealed class Node
    {
        public Interval Interval;
        public long Max;
        public Node? Left;
        public Node? Right;
    }

    private Node? _root;

    public void Insert(long start, long end) => _root = InsertRecursive(_root, new Interval(start, end));

    private static Node InsertRecursive(Node? node, Interval interval)
    {
        if (node == null) return new Node { Interval = interval, Max = interval.End };

        if (interval.Start < node.Interval.Start)
            node.Left = InsertRecursive(node.Left, interval);
        else
            node.Right = InsertRecursive(node.Right, interval);

        node.Max = Math.Max(node.Max, interval.End);
        return node;
    }

    public List<Interval> Query(long start, long end)
    {
        var results = new List<Interval>();
        QueryRecursive(_root, start, end, results);
        return results;
    }

    private static void QueryRecursive(Node? node, long start, long end, List<Interval> results)
    {
        if (node == null) return;

        if (node.Interval.Start <= end && node.Interval.End >= start)
            results.Add(node.Interval);

        if (node.Left != null && node.Left.Max >= start)
            QueryRecursive(node.Left, start, end, results);

        QueryRecursive(node.Right, start, end, results);
    }
}

#endregion

#region Sparse Table Range Query

public static class SparseTableMin
{
    public static int[,] Build(int[] data)
    {
        int n = data.Length;
        int k = 1;
        while ((1 << k) <= n) k++;
        var table = new int[k, n];
        for (int i = 0; i < n; i++) table[0, i] = data[i];

        for (int j = 1; j < k; j++)
        {
            for (int i = 0; i + (1 << j) <= n; i++)
            {
                table[j, i] = Math.Min(table[j - 1, i], table[j - 1, i + (1 << (j - 1))]);
            }
        }
        return table;
    }

    public static int Query(int[,] table, int[] logTable, int l, int r)
    {
        int j = logTable[r - l + 1];
        return Math.Min(table[j, l], table[j, r - (1 << j) + 1]);
    }

    public static int[] BuildLog(int n)
    {
        var log = new int[n + 1];
        for (int i = 2; i <= n; i++) log[i] = log[i / 2] + 1;
        return log;
    }
}

#endregion

#region Heavy Light Decomposition

public sealed class HeavyLightDecomposition
{
    private readonly List<int>[] _adjacency;
    private readonly int[] _parent;
    private readonly int[] _depth;
    private readonly int[] _heavy;
    private readonly int[] _head;
    private readonly int[] _position;
    private int _currentPosition;

    public HeavyLightDecomposition(int n)
    {
        _adjacency = new List<int>[n];
        for (int i = 0; i < n; i++) _adjacency[i] = new List<int>();
        _parent = new int[n];
        _depth = new int[n];
        _heavy = new int[n];
        _head = new int[n];
        _position = new int[n];
        Array.Fill(_heavy, -1);
    }

    public void AddEdge(int u, int v)
    {
        _adjacency[u].Add(v);
        _adjacency[v].Add(u);
    }

    public void Build(int root)
    {
        Dfs(root, -1, 0);
        Decompose(root, root);
    }

    private int Dfs(int node, int parent, int depth)
    {
        _parent[node] = parent;
        _depth[node] = depth;
        int size = 1;
        int maxSubtree = 0;

        foreach (int child in _adjacency[node])
        {
            if (child == parent) continue;
            int childSize = Dfs(child, node, depth + 1);
            size += childSize;
            if (childSize > maxSubtree)
            {
                maxSubtree = childSize;
                _heavy[node] = child;
            }
        }
        return size;
    }

    private void Decompose(int node, int head)
    {
        _head[node] = head;
        _position[node] = _currentPosition++;

        if (_heavy[node] != -1)
            Decompose(_heavy[node], head);

        foreach (int child in _adjacency[node])
        {
            if (child != _parent[node] && child != _heavy[node])
                Decompose(child, child);
        }
    }

    public int Lca(int u, int v)
    {
        while (_head[u] != _head[v])
        {
            if (_depth[_head[u]] > _depth[_head[v]]) u = _parent[_head[u]];
            else v = _parent[_head[v]];
        }
        return _depth[u] < _depth[v] ? u : v;
    }

    public IEnumerable<(int left, int right)> PathQuery(int u, int v)
    {
        while (_head[u] != _head[v])
        {
            if (_depth[_head[u]] > _depth[_head[v]])
            {
                yield return (_position[_head[u]], _position[u]);
                u = _parent[_head[u]];
            }
            else
            {
                yield return (_position[_head[v]], _position[v]);
                v = _parent[_head[v]];
            }
        }

        if (_depth[u] > _depth[v])
            yield return (_position[v], _position[u]);
        else
            yield return (_position[u], _position[v]);
    }
}

#endregion

#region Centroid Decomposition

public sealed class CentroidDecomposition
{
    private readonly List<int>[] _adjacency;
    private readonly bool[] _removed;
    private readonly int[] _subtreeSize;
    private readonly int[] _centroidParent;
    private int _n;

    public CentroidDecomposition(int n)
    {
        _n = n;
        _adjacency = new List<int>[n];
        for (int i = 0; i < n; i++) _adjacency[i] = new List<int>();
        _removed = new bool[n];
        _subtreeSize = new int[n];
        _centroidParent = new int[n];
        Array.Fill(_centroidParent, -1);
    }

    public void AddEdge(int u, int v)
    {
        _adjacency[u].Add(v);
        _adjacency[v].Add(u);
    }

    public void Build(int root = 0) => BuildRecursive(root, -1);

    private void BuildRecursive(int entry, int parent)
    {
        int centroid = FindCentroid(entry);
        _centroidParent[centroid] = parent;
        _removed[centroid] = true;

        foreach (int neighbor in _adjacency[centroid])
        {
            if (!_removed[neighbor])
                BuildRecursive(neighbor, centroid);
        }
    }

    private int FindCentroid(int entry)
    {
        ComputeSizes(entry, -1);
        int totalSize = _subtreeSize[entry];
        return FindCentroidRecursive(entry, -1, totalSize);
    }

    private void ComputeSizes(int node, int parent)
    {
        _subtreeSize[node] = 1;
        foreach (int child in _adjacency[node])
        {
            if (child == parent || _removed[child]) continue;
            ComputeSizes(child, node);
            _subtreeSize[node] += _subtreeSize[child];
        }
    }

    private int FindCentroidRecursive(int node, int parent, int totalSize)
    {
        foreach (int child in _adjacency[node])
        {
            if (child == parent || _removed[child]) continue;
            if (_subtreeSize[child] > totalSize / 2)
                return FindCentroidRecursive(child, node, totalSize);
        }
        return node;
    }
}

#endregion

#region Treap with Implicit Keys

public sealed class ImplicitTreap<T>
{
    private sealed class Node
    {
        public T Value = default!;
        public int Priority;
        public int Size = 1;
        public Node? Left;
        public Node? Right;
    }

    private readonly Random _random = new(42);
    private Node? _root;

    public int Count => Size(_root);

    public void Insert(int index, T value) => _root = Insert(_root, index, new Node { Value = value, Priority = _random.Next() });

    private Node Insert(Node? node, int index, Node newNode)
    {
        if (node == null) return newNode;
        int leftSize = Size(node.Left);
        if (index <= leftSize)
        {
            node.Left = Insert(node.Left, index, newNode);
            if (node.Left.Priority < node.Priority)
                node = RotateRight(node);
        }
        else
        {
            node.Right = Insert(node.Right, index - leftSize - 1, newNode);
            if (node.Right.Priority < node.Priority)
                node = RotateLeft(node);
        }
        Update(node);
        return node;
    }

    private static int Size(Node? node) => node?.Size ?? 0;

    private static void Update(Node node) => node.Size = 1 + Size(node.Left) + Size(node.Right);

    private static Node RotateRight(Node y)
    {
        var x = y.Left!;
        y.Left = x.Right;
        x.Right = y;
        Update(y);
        Update(x);
        return x;
    }

    private static Node RotateLeft(Node x)
    {
        var y = x.Right!;
        x.Right = y.Left;
        y.Left = x;
        Update(x);
        Update(y);
        return y;
    }

    public T this[int index]
    {
        get
        {
            var node = _root;
            while (node != null)
            {
                int leftSize = Size(node.Left);
                if (index < leftSize) node = node.Left;
                else if (index == leftSize) return node.Value;
                else
                {
                    index -= leftSize + 1;
                    node = node.Right;
                }
            }
            throw new IndexOutOfRangeException();
        }
    }
}

#endregion

#region Persistent Segment Tree

public sealed class PersistentSegmentTree
{
    private sealed class Node
    {
        public long Sum;
        public Node? Left;
        public Node? Right;
    }

    private readonly List<Node?> _roots = new();
    private readonly int _size;

    public PersistentSegmentTree(int size)
    {
        _size = size;
        _roots.Add(Build(0, size - 1));
    }

    private static Node Build(int lo, int hi)
    {
        var node = new Node();
        if (lo < hi)
        {
            int mid = (lo + hi) / 2;
            node.Left = Build(lo, mid);
            node.Right = Build(mid + 1, hi);
        }
        return node;
    }

    public int Update(int version, int index, long value)
    {
        _roots.Add(UpdateRecursive(_roots[version], 0, _size - 1, index, value));
        return _roots.Count - 1;
    }

    private static Node UpdateRecursive(Node? node, int lo, int hi, int index, long value)
    {
        var newNode = new Node
        {
            Left = node?.Left,
            Right = node?.Right,
            Sum = (node?.Sum ?? 0) + value
        };

        if (lo == hi) return newNode;

        int mid = (lo + hi) / 2;
        if (index <= mid)
            newNode.Left = UpdateRecursive(node?.Left, lo, mid, index, value);
        else
            newNode.Right = UpdateRecursive(node?.Right, mid + 1, hi, index, value);

        return newNode;
    }

    public long Query(int version, int l, int r)
    {
        return QueryRecursive(_roots[version], 0, _size - 1, l, r);
    }

    private static long QueryRecursive(Node? node, int lo, int hi, int l, int r)
    {
        if (node == null || l > hi || r < lo) return 0;
        if (l <= lo && hi <= r) return node.Sum;

        int mid = (lo + hi) / 2;
        return QueryRecursive(node.Left, lo, mid, l, r)
             + QueryRecursive(node.Right, mid + 1, hi, l, r);
    }
}

#endregion

#region Wavelet Tree

public sealed class WaveletTree
{
    private sealed class Node
    {
        public int[] PrefixSums = Array.Empty<int>();
        public Node? Left;
        public Node? Right;
        public int Lo, Hi;
    }

    private readonly Node _root;

    public WaveletTree(int[] data, int lo, int hi)
    {
        _root = Build(data, lo, hi);
    }

    private static Node Build(int[] data, int lo, int hi)
    {
        var node = new Node { Lo = lo, Hi = hi };
        if (lo == hi || data.Length == 0) return node;

        int mid = (lo + hi) / 2;
        var prefixSums = new int[data.Length + 1];
        var leftData = new List<int>();
        var rightData = new List<int>();

        for (int i = 0; i < data.Length; i++)
        {
            if (data[i] <= mid)
            {
                leftData.Add(data[i]);
                prefixSums[i + 1] = prefixSums[i] + 1;
            }
            else
            {
                rightData.Add(data[i]);
                prefixSums[i + 1] = prefixSums[i];
            }
        }

        node.PrefixSums = prefixSums;
        node.Left = Build(leftData.ToArray(), lo, mid);
        node.Right = Build(rightData.ToArray(), mid + 1, hi);
        return node;
    }

    public int KthSmallest(int l, int r, int k)
    {
        return KthSmallestRecursive(_root, l, r, k);
    }

    private static int KthSmallestRecursive(Node node, int l, int r, int k)
    {
        if (node.Lo == node.Hi) return node.Lo;

        int leftCount = node.PrefixSums[r + 1] - node.PrefixSums[l];
        int mid = (node.Lo + node.Hi) / 2;

        if (k <= leftCount)
        {
            int newL = node.PrefixSums[l];
            int newR = node.PrefixSums[r + 1] - 1;
            return KthSmallestRecursive(node.Left!, newL, newR, k);
        }
        else
        {
            int newL = l - node.PrefixSums[l];
            int newR = r - node.PrefixSums[r + 1];
            return KthSmallestRecursive(node.Right!, newL, newR, k - leftCount);
        }
    }
}

#endregion

#region Disjoint Sparse Table

public static class DisjointSparseTable
{
    public static int[,] Build(int[] data, Func<int, int, int> op)
    {
        int n = data.Length;
        int log = 1;
        while
      }
}
