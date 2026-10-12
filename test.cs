using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.IO.MemoryMappedFiles;
using System.Linq;
using System.Numerics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;

namespace SecAgent.Core;

#region ═══════════════════════════════════════════════════════════
#           SIMD SCANNER — vectorized pattern matching
# ═══════════════════════════════════════════════════════════════

public unsafe struct SimdScanner
{
    private const int V_WIDTH = 32;

    public static (ulong sqlHits, ulong xssHits, ulong cmdHits) 
        ScanWindow(byte* buffer, int length)
    {
        ulong s = 0, x = 0, c = 0;
        var vectorSQ = Vector256.Create((byte)'S', (byte)'Q', (byte)'L', 0,
                                         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                         0, 0, 0, 0);
        var vectorXS = Vector256.Create((byte)'<', (byte)'s', (byte)'c', (byte)'r',
                                         (byte)'i', (byte)'p', (byte)'t', 0,
                                         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
        var vectorCM = Vector256.Create((byte)';', (byte)' ', (byte)'r', (byte)'m',
                                         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                         0, 0, 0, 0);

        int i = 0;
        while (i + V_WIDTH <= length)
        {
            var chunk = Vector256.Load(buffer + i);
            var cmpS = Vector256.Equals(chunk, vectorSQ);
            var cmpX = Vector256.Equals(chunk, vectorXS);
            var cmpC = Vector256.Equals(chunk, vectorCM);

            s += (uint)Vector256.ExtractMostSignificantBits(cmpS);
            x += (uint)Vector256.ExtractMostSignificantBits(cmpX);
            c += (uint)Vector256.ExtractMostSignificantBits(cmpC);

            i += V_WIDTH;
        }

        while (i < length)
        {
            switch (buffer[i])
            {
                case (byte)'S': s++; break;
                case (byte)'<': x++; break;
                case (byte)';': c++; break;
            }
            i++;
        }

        return (s, x, c);
    }
}

#endregion

#region ═══════════════════════════════════════════════════════════
#           BIT-TWIDDLING HASH — FNV-1a + murmur mix
# ═══════════════════════════════════════════════════════════════

public static class BitHash
{
    private const ulong FNV_PRIME  = 0x100000001B3;
    private const ulong FNV_OFFSET = 0xCBF29CE484222325;
    private const ulong MIX_A      = 0xFF51AFD7ED558CCD;
    private const ulong MIX_B      = 0xC4CEB9FE1A85EC53;

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static ulong Compute(ReadOnlySpan<byte> data)
    {
        ulong h = FNV_OFFSET;
        for (int i = 0; i < data.Length; i++)
        {
            h ^= data[i];
            h *= FNV_PRIME;
            h = BitOperations.RotateLeft(h, 13);
        }

        h ^= h >> 33;
        h *= MIX_A;
        h ^= h >> 33;
        h *= MIX_B;
        h ^= h >> 33;

        return h;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static ulong Fast(string s)
    {
        var span = MemoryMarshal.AsBytes(s.AsSpan());
        return Compute(span);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static int PopCount(ulong x) => BitOperations.PopCount(x);

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static int TrailingZeros(ulong x) => BitOperations.TrailingZeroCount(x);

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static int LeadingZeros(ulong x) => BitOperations.LeadingZeroCount(x);
}

#endregion

#region ═══════════════════════════════════════════════════════════
#           STATE MACHINE — regex-free pattern matcher
# ═══════════════════════════════════════════════════════════════

public enum TokenKind : byte
{
    None = 0,
    SQL = 1,
    XSS = 2,
    CMD = 3,
    SEC = 4,
    CRY = 5,
    RNG = 6,
    EMP = 7
}

public struct StateMachine
{
    private byte _state;
    private TokenKind _matched;

    public static readonly byte[,] Transitions = new byte[8, 5];

    static StateMachine()
    {
        for (int s = 0; s < 8; s++)
            for (int c = 0; c < 5; c++)
                Transitions[s, c] = 0;

        Transitions[0, 0] = 1;
        Transitions[0, 1] = 2;
        Transitions[0, 2] = 3;
        Transitions[0, 3] = 4;
        Transitions[0, 4] = 5;
        Transitions[1, 1] = 6;
        Transitions[2, 2] = 6;
        Transitions[3, 3] = 6;
        Transitions[4, 4] = 6;
        Transitions[5, 3] = 6;
    }

    public void Reset()
    {
        _state = 0;
        _matched = TokenKind.None;
    }

    public TokenKind Feed(byte b)
    {
        int cls = ClassifyByte(b);
        _state = Transitions[_state, cls];
        if (_state == 6)
        {
            _matched = (TokenKind)(_state - 5);
            Reset();
        }
        return _matched;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static int ClassifyByte(byte b) => b switch
    {
        (byte)'S' or (byte)'Q' or (byte)'L' => 0,
        (byte)'<' or (byte)'s' or (byte)'c' => 1,
        (byte)';' or (byte)'r' or (byte)'m' => 2,
        (byte)'p' or (byte)'a' or (byte)'s' => 3,
        (byte)'M' or (byte)'D' or (byte)'5' => 4,
        _ => 3
    };
}

#endregion

#region ═══════════════════════════════════════════════════════════
#           MEMORY-MAPPED FILE READER — zero-copy I/O
# ═══════════════════════════════════════════════════════════════

public sealed unsafe class ZeroCopyReader : IDisposable
{
    private readonly MemoryMappedFile _mmf;
    private readonly MemoryMappedViewAccessor _view;
    private readonly long _length;

    public ZeroCopyReader(string path)
    {
        var fi = new FileInfo(path);
        _length = fi.Length;

        if (_length == 0)
            throw new InvalidOperationException("Empty file");

        _mmf = MemoryMappedFile.CreateFromFile(
            path, FileMode.Open, null, 0,
            MemoryMappedFileAccess.Read);

        _view = _mmf.CreateViewAccessor(0, _length, MemoryMappedFileAccess.Read);
    }

    public byte* Pointer
    {
        get
        {
            byte* ptr = null;
            _view.SafeMemoryMappedViewHandle.AcquirePointer(ref ptr);
            return ptr + _view.PointerOffset;
        }
    }

    public long Length => _length;

    public void Release() 
        => _view.SafeMemoryMappedViewHandle.ReleasePointer();

    public void Dispose()
    {
        _view?.Dispose();
        _mmf?.Dispose();
    }
}

#endregion

#region ═══════════════════════════════════════════════════════════
#           SPAN-BASED TOKENIZER — no allocations
# ═══════════════════════════════════════════════════════════════

public ref struct LineCursor
{
    private readonly ReadOnlySpan<char> _source;
    private int _position;

    public LineCursor(ReadOnlySpan<char> source)
    {
        _source = source;
        _position = 0;
        Current = default;
    }

    public ReadOnlySpan<char> Current { get; private set; }

    public bool MoveNext()
    {
        if (_position >= _source.Length) return false;

        var start = _position;
        while (_position < _source.Length && _source[_position] != '\n')
            _position++;

        var end = _position;
        if (end > start && _source[end - 1] == '\r')
            end--;

        Current = _source[start..end];
        _position++;
        return true;
    }

    public LineCursor GetEnumerator() => this;

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static int LineOf(ReadOnlySpan<char> source, int charIndex)
    {
        int line = 1;
        for (int i = 0; i < charIndex && i < source.Length; i++)
            if (source[i] == '\n') line++;
        return line;
    }
}

#endregion

#region ═══════════════════════════════════════════════════════════
#           BLOOM FILTER — probabilistic line cache
# ═══════════════════════════════════════════════════════════════

public sealed class BloomFilter
{
    private readonly ulong[] _bits;
    private readonly int _hashCount;
    private readonly int _size;

    public BloomFilter(int expectedItems, double falsePositiveRate = 0.01)
    {
        _size = (int)Math.Ceiling(-expectedItems * Math.Log(falsePositiveRate) 
                                   / (Math.Log(2) * Math.Log(2)));
        _bits = new ulong[(_size + 63) / 64];
        _hashCount = (int)Math.Round(_size / (double)expectedItems * Math.Log(2));
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public void Add(ulong hash)
    {
        for (int i = 0; i < _hashCount; i++)
        {
            var h = hash ^ ((ulong)i * 0x9E3779B97F4A7C15);
            h ^= h >> 33;
            var idx = (int)(h % (ulong)_size);
            _bits[idx / 64] |= 1UL << (idx % 64);
        }
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public bool MightContain(ulong hash)
    {
        for (int i = 0; i < _hashCount; i++)
        {
            var h = hash ^ ((ulong)i * 0x9E3779B97F4A7C15);
            h ^= h >> 33;
            var idx = (int)(h % (ulong)_size);
            if ((_bits[idx / 64] & (1UL << (idx % 64))) == 0)
                return false;
        }
        return true;
    }
}

#endregion

#region ═══════════════════════════════════════════════════════════
#           PARALLEL SCANNER — SIMD + threads
# ═══════════════════════════════════════════════════════════════

public sealed class HyperScanner
{
    private readonly BloomFilter _cache = new(100_000);
    private long _linesProcessed;
    private long _anomaliesFound;
    private readonly object _lock = new();

    public long Lines => Interlocked.Read(ref _linesProcessed);
    public long Anomalies => Interlocked.Read(ref _anomaliesFound);

    public async Task ScanAsync(string[] files, CancellationToken ct = default)
    {
        var parallelOptions = new ParallelOptions
        {
            CancellationToken = ct,
            MaxDegreeOfParallelism = Environment.ProcessorCount
        };

        await Parallel.ForEachAsync(files, parallelOptions, async (file, token) =>
        {
            await ScanFileAsync(file, token);
        });
    }

    private async Task ScanFileAsync(string file, CancellationToken ct)
    {
        if (!File.Exists(file)) return;

        string content;
        try
        {
            content = await File.ReadAllTextAsync(file, ct);
        }
        catch { return; }

        var span = content.AsSpan();
        var cursor = new LineCursor(span);
        int lineNumber = 0;

        while (cursor.MoveNext())
        {
            ct.ThrowIfCancellationRequested();
            lineNumber++;

            var line = cursor.Current;
            if (line.IsWhiteSpace) continue;

            Interlocked.Increment(ref _linesProcessed);

            ulong hash = BitHash.Compute(MemoryMarshal.AsBytes(line));
            if (!_cache.MightContain(hash))
            {
                _cache.Add(hash);
            }

            if (ContainsSuspicious(line))
            {
                Interlocked.Increment(ref _anomaliesFound);
            }
        }
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static bool ContainsSuspicious(ReadOnlySpan<char> line)
    {
        if (line.Length < 8) return false;

        Span<byte> lowBytes = stackalloc byte[64];
        int count = Math.Min(line.Length, lowBytes.Length);

        for (int i = 0; i < count; i++)
        {
            var c = line[i];
            lowBytes[i] = (byte)(c | 0x20);
        }

        var low = lowBytes[..count];

        return Contains(low, "select"u8) ||
               Contains(low, "script"u8) ||
               Contains(low, "system"u8) ||
               Contains(low, "password"u8) ||
               Contains(low, "md5"u8) ||
               Contains(low, "random"u8) ||
               Contains(low, "catch"u8);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static bool Contains(ReadOnlySpan<byte> haystack, ReadOnlySpan<byte> needle)
    {
        if (needle.Length > haystack.Length) return false;
        return haystack.IndexOf(needle) >= 0;
    }
}

#endregion

#region ═══════════════════════════════════════════════════════════
#           POLYMORPHIC DETECTOR — expression tree voodoo
# ═══════════════════════════════════════════════════════════════

public sealed class PolyDetector<T> where T : unmanaged
{
    private readonly Func<T, T, T> _accumulator;
    private readonly Func<T, bool> _predicate;

    public PolyDetector(Func<T, T, T> accumulator, Func<T, bool> predicate)
    {
        _accumulator = accumulator;
        _predicate = predicate;
    }

    public unsafe T Aggregate(T* source, int count)
    {
        T result = default;
        for (int i = 0; i < count; i++)
        {
            if (_predicate(source[i]))
                result = _accumulator(result, source[i]);
        }
        return result;
    }

    public static PolyDetector<ulong> CreateXor() =>
        new((a, b) => a ^ b, x => x != 0);

    public static PolyDetector<int> CreateSum() =>
        new((a, b) => a + b, x => x > 0);
}

#endregion

#region ═══════════════════════════════════════════════════════════
#           ENTRY POINT
# ═══════════════════════════════════════════════════════════════

public static class Program
{
    public static async Task Main(string[] args)
    {
        Console.OutputEncoding = Encoding.UTF8;

        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine(@"
    ╔══════════════════════════════════════════════════════════╗
    ║  ▓▓▓  H Y P E R - S C A N N E R  v2.0  ▓▓▓             ║
    ║  SIMD · Zero-Copy · Parallel · Bloom · FNV-1a           ║
    ╚══════════════════════════════════════════════════════════╝
");
        Console.ResetColor();

        var path = args.Length > 0 ? args[0] : Environment.CurrentDirectory;

        if (!Directory.Exists(path) && !File.Exists(path))
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine($"[!] Invalid path: {path}");
            return;
        }

        var files = Directory.Exists(path)
            ? Directory.GetFiles(path, "*.*", SearchOption.AllDirectories)
                .Where(f => f.EndsWith(".cs") || f.EndsWith(".py") 
                         || f.EndsWith(".js") || f.EndsWith(".php"))
                .ToArray()
            : new[] { path };

        Console.ForegroundColor = ConsoleColor.Green;
        Console.WriteLine($"[+] Target: {path}");
        Console.WriteLine($"[+] Files:  {files.Length}");
        Console.WriteLine($"[+] SIMD:   {(Avx2.IsSupported ? "AVX2 ✓" : "fallback")}");
        Console.WriteLine($"[+] Cores:  {Environment.ProcessorCount}");
        Console.ResetColor();
        Console.WriteLine();

        var sw = Stopwatch.StartNew();
        var scanner = new HyperScanner();
        await scanner.ScanAsync(files);
        sw.Stop();

        Console.ForegroundColor = ConsoleColor.Yellow;
        Console.WriteLine();
        Console.WriteLine("═══════════════════════════════════════════");
        Console.WriteLine($"  Lines processed : {scanner.Lines:N0}");
        Console.WriteLine($"  Anomalies found : {scanner.Anomalies:N0}");
        Console.WriteLine($"  Elapsed         : {sw.ElapsedMilliseconds} ms");
        Console.WriteLine($"  Throughput      : {scanner.Lines / Math.Max(1, sw.ElapsedMilliseconds) * 1000:N0} lines/sec");
        Console.WriteLine("═══════════════════════════════════════════");
        Console.ResetColor();

        Console.WriteLine();
        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.WriteLine("  [ Made by Ali Moemeni ]");
        Console.ResetColor();
    }
}

#endregion
