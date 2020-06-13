package cryptolib;

import org.openjdk.jmh.annotations.*;
import org.openjdk.jmh.infra.Blackhole;

import java.util.Base64;
import java.util.concurrent.TimeUnit;

public class TripleDesBenchmark {

    @State(Scope.Thread)
    public static class KeyState {
        public String hexKey = "000102030405060708090A0B0C0D0E0F";
        public String keySeed = "My uinque id";
        String plainMessage = "12345678";
        public byte[] bPlainMessage = plainMessage.getBytes();
        String cipherMessage = "eFklvL5qUJQ=";
        public byte[] bCipherMessage = Base64.getDecoder().decode(cipherMessage);
        public byte[] bKey = TripleDes.buildKey(keySeed);    
    }

    @Benchmark 
    @BenchmarkMode(Mode.Throughput)
    @OutputTimeUnit(TimeUnit.SECONDS)
    @Warmup(iterations = 1, time = 1, timeUnit = TimeUnit.SECONDS)
    @Measurement(iterations = 1, time = 10, timeUnit = TimeUnit.SECONDS)
    @Fork(value = 1, warmups = 1)
    public void testMakeupKey(final KeyState state, final Blackhole blackhole) {
        final byte[] bKey = TripleDes.makeupKey(state.hexKey);
        blackhole.consume(bKey);
    }

    @Benchmark 
    @BenchmarkMode(Mode.Throughput)
    @OutputTimeUnit(TimeUnit.SECONDS)
    @Warmup(iterations = 1, time = 1, timeUnit = TimeUnit.SECONDS)
    @Measurement(iterations = 1, time = 10, timeUnit = TimeUnit.SECONDS)
    @Fork(value = 1, warmups = 1)
    public void testBuildKey(final KeyState state, final Blackhole blackhole) {
        final byte[] bKey = TripleDes.buildKey(state.keySeed);
        blackhole.consume(bKey);
    }

    @Benchmark 
    @BenchmarkMode(Mode.Throughput)
    @OutputTimeUnit(TimeUnit.SECONDS)
    @Warmup(iterations = 1, time = 1, timeUnit = TimeUnit.SECONDS)
    @Measurement(iterations = 1, time = 10, timeUnit = TimeUnit.SECONDS)
    @Fork(value = 1, warmups = 1)
    public void testEncrypt(final KeyState state, final Blackhole blackhole) {
        final byte[] bKey = TripleDes.encrypt(state.bPlainMessage, state.bKey, "DESede/ECB/NoPadding");
        blackhole.consume(bKey);
    }

    @Benchmark 
    @BenchmarkMode(Mode.Throughput)
    @OutputTimeUnit(TimeUnit.SECONDS)
    @Warmup(iterations = 1, time = 1, timeUnit = TimeUnit.SECONDS)
    @Measurement(iterations = 1, time = 10, timeUnit = TimeUnit.SECONDS)
    @Fork(value = 1, warmups = 1)
    @Threads(value = 1)
    public void testDecrypt(final KeyState state, final Blackhole blackhole) {
        final byte[] bKey = TripleDes.encrypt(state.bCipherMessage, state.bKey, "DESede/ECB/NoPadding");
        blackhole.consume(bKey);
    }
}
