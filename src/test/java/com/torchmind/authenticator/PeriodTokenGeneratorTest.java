/*
 * Copyright 2016 Johannes Donath <johannesd@torchmind.com>
 * and other copyright owners as documented in the project's IP log.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * 	http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.torchmind.authenticator;

import org.junit.Assert;
import org.junit.Test;

import java.time.Instant;

import javax.crypto.SecretKey;

/**
 * @author <a href="mailto:johannesd@torchmind.com">Johannes Donath</a>
 */
public class PeriodTokenGeneratorTest {

    @Test
    public void buildUri() throws Exception {
        PeriodTokenGenerator generator = TokenGenerator.builder().createPeriodGenerator("Issuer");
        SecretKey key = generator.parseCode("KLYQV62WLKEKRQQM");

        Assert.assertEquals("otpauth://totp/Issuer:AccountName1?secret=KLYQV62WLKEKRQQM&issuer=Issuer&period=30&algorithm=SHA1&digits=6", generator.buildUri(key, "AccountName1").toString());
        Assert.assertEquals("otpauth://totp/Issuer:AccountName2?secret=KLYQV62WLKEKRQQM&issuer=Issuer&period=30&algorithm=SHA1&digits=6", generator.buildUri(key, "AccountName2").toString());
    }

    @Test
    public void generateCode() throws Exception {
        PeriodTokenGenerator generator = TokenGenerator.builder().createPeriodGenerator("Issuer");
        SecretKey key = generator.parseCode("KLYQV62WLKEKRQQM");

        Assert.assertEquals("565580", generator.generateCode(key, Instant.ofEpochSecond(1)));
        Assert.assertEquals("565580", generator.generateCode(key, Instant.ofEpochSecond(2)));
        Assert.assertEquals("565580", generator.generateCode(key, Instant.ofEpochSecond(10)));
        Assert.assertEquals("565580", generator.generateCode(key, Instant.ofEpochSecond(20)));
        Assert.assertEquals("565580", generator.generateCode(key, Instant.ofEpochSecond(29)));
        Assert.assertEquals("707879", generator.generateCode(key, Instant.ofEpochSecond(30)));
        Assert.assertEquals("707879", generator.generateCode(key, Instant.ofEpochSecond(40)));
        Assert.assertEquals("707879", generator.generateCode(key, Instant.ofEpochSecond(50)));
        Assert.assertEquals("707879", generator.generateCode(key, Instant.ofEpochSecond(59)));
        Assert.assertEquals("981077", generator.generateCode(key, Instant.ofEpochSecond(60)));
        Assert.assertEquals("981077", generator.generateCode(key, Instant.ofEpochSecond(70)));
        Assert.assertEquals("981077", generator.generateCode(key, Instant.ofEpochSecond(80)));
        Assert.assertEquals("981077", generator.generateCode(key, Instant.ofEpochSecond(89)));
    }
}
