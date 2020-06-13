/*
 * Copyright (c) 2014, Oracle America, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *  * Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 *  * Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 *  * Neither the name of Oracle nor the names of its contributors may be used
 *    to endorse or promote products derived from this software without
 *    specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
 * THE POSSIBILITY OF SUCH DAMAGE.
 */

package cryptolib;

import org.openjdk.jmh.annotations.*;
import org.openjdk.jmh.infra.Blackhole;

import java.util.concurrent.TimeUnit;

public class PinBlockBenchmark {

    @State(Scope.Thread)
    public static class KeyState {
        public String pin = "1234";
        public String pan = "6037997390214444";
        String hexKey = "000102030405060708090A0B0C0D0E0F";
        public byte[] bKey = TripleDes.makeupKey(hexKey);
        public String extendedPinBlock = "C7933494F32B43F6";
    }

    @Benchmark 
    @BenchmarkMode(Mode.Throughput)
    @OutputTimeUnit(TimeUnit.SECONDS)
    @Warmup(iterations = 1, time = 1, timeUnit = TimeUnit.SECONDS)
    @Measurement(iterations = 1, time = 10, timeUnit = TimeUnit.SECONDS)
    @Fork(value = 1, warmups = 1)
    public void testEncode(KeyState state, Blackhole blackhole) {
        String extendedPinBlock = Pinblock.encode(state.pin, state.pan, state.bKey);
        blackhole.consume(extendedPinBlock);
    }

    @Benchmark 
    @BenchmarkMode(Mode.Throughput)
    @OutputTimeUnit(TimeUnit.SECONDS)
    @Warmup(iterations = 1, time = 1, timeUnit = TimeUnit.SECONDS)
    @Measurement(iterations = 1, time = 10, timeUnit = TimeUnit.SECONDS)
    @Fork(value = 1, warmups = 1)
    public void testDecode(KeyState state, Blackhole blackhole) {
        String pin = Pinblock.decode(state.extendedPinBlock, state.pan, state.bKey);
        blackhole.consume(pin);
    }

}
