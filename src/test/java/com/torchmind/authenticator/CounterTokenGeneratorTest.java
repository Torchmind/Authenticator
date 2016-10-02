package com.torchmind.authenticator;

import org.junit.Assert;
import org.junit.Test;

import javax.crypto.SecretKey;

/**
 * @author <a href="mailto:johannesd@torchmind.com">Johannes Donath</a>
 */
public class CounterTokenGeneratorTest {

    @Test
    public void buildUri() throws Exception {
        CounterTokenGenerator generator = TokenGenerator.builder().createCounterGenerator("Issuer");
        SecretKey key = generator.parseCode("KLYQV62WLKEKRQQM");

        Assert.assertEquals("otpauth://hotp/Issuer:AccountName?secret=KLYQV62WLKEKRQQM&issuer=Issuer&counter=1&algorithm=SHA1&digits=6", generator.buildUri(key, "AccountName", 1).toString());
        Assert.assertEquals("otpauth://hotp/Issuer:AccountName?secret=KLYQV62WLKEKRQQM&issuer=Issuer&counter=2&algorithm=SHA1&digits=6", generator.buildUri(key, "AccountName", 2).toString());
        Assert.assertEquals("otpauth://hotp/Issuer:AccountName?secret=KLYQV62WLKEKRQQM&issuer=Issuer&counter=3&algorithm=SHA1&digits=6", generator.buildUri(key, "AccountName", 3).toString());

        Assert.assertEquals("otpauth://hotp/Issuer:AccountName2?secret=KLYQV62WLKEKRQQM&issuer=Issuer&counter=1&algorithm=SHA1&digits=6", generator.buildUri(key, "AccountName2", 1).toString());
        Assert.assertEquals("otpauth://hotp/Issuer:AccountName3?secret=KLYQV62WLKEKRQQM&issuer=Issuer&counter=1&algorithm=SHA1&digits=6", generator.buildUri(key, "AccountName3", 1).toString());
    }

    @Test
    public void generateCode() throws Exception {
        CounterTokenGenerator generator = TokenGenerator.builder().createCounterGenerator("Issuer");
        SecretKey key = generator.parseCode("KLYQV62WLKEKRQQM");

        Assert.assertEquals("565580", generator.generateCode(key, 0));
        Assert.assertEquals("707879", generator.generateCode(key, 1));
        Assert.assertEquals("981077", generator.generateCode(key, 2));
        Assert.assertEquals("771141", generator.generateCode(key, 3));
        Assert.assertEquals("729385", generator.generateCode(key, 4));
    }
}
