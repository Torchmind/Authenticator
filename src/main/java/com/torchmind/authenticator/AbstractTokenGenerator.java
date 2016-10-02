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

import org.apache.commons.codec.binary.Base32;

import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.annotation.Nonnegative;
import javax.annotation.Nonnull;
import javax.annotation.concurrent.Immutable;
import javax.annotation.concurrent.ThreadSafe;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

/**
 * Provides an abstract token generator implementation which provides the most basic elements of the
 * token generator specification.
 *
 * @author <a href="mailto:johannesd@torchmind.com">Johannes Donath</a>
 */
@Immutable
@ThreadSafe
abstract class AbstractTokenGenerator implements TokenGenerator {
    private final Algorithm algorithm;
    private final int digits;
    private final String issuer;
    private final int digitModulo;

    AbstractTokenGenerator(@Nonnull Algorithm algorithm, @Nonnegative int digits, @Nonnull String issuer) {
        this.algorithm = algorithm;
        this.digits = digits;
        this.issuer = issuer;

        this.digitModulo = (int) Math.pow(10, digits);
    }

    /**
     * {@inheritDoc}
     */
    @Nonnull
    @Override
    public String buildHandshakeCode(@Nonnull SecretKey secretKey, boolean humanReadable) {
        String code = (new Base32()).encodeAsString(secretKey.getEncoded());

        if (humanReadable) {
            String tmp = "";

            for (int i = 1; i < code.length(); ++i) {
                tmp += code.charAt((i - 1));

                if ((i % 4) == 0) {
                    tmp += " ";
                }
            }

            if (tmp.charAt((tmp.length() - 1)) == ' ') {
                code = tmp.substring(0, (tmp.length() - 1)).toLowerCase();
            } else {
                code = tmp.toLowerCase();
            }
        }

        return code;
    }

    /**
     * Generates a code based on a secret key and challenge.
     *
     * @param secretKey a secret key.
     * @param challenge a challenge.
     * @return a code.
     */
    @Nonnull
    protected String generateCode(@Nonnull SecretKey secretKey, @Nonnull byte[] challenge) {
        try {
            Mac mac = Mac.getInstance("Hmac" + this.algorithm.name());
            mac.init(secretKey);

            byte[] hash = mac.doFinal(challenge);
            int offset = hash[hash.length - 1] & 0x0F;

            ByteBuffer buffer = ByteBuffer.allocate(4).put(hash, offset, 4);
            buffer.flip();

            return String.format("%0" + this.digits + "d", (buffer.getInt() & 0x7FFFFFFF) % this.digitModulo);
        } catch (NoSuchAlgorithmException ex) {
            throw new UnsupportedOperationException("The specified algorithm is not supported by this Java VM implementation: " + ex.getMessage(), ex);
        } catch (InvalidKeyException ex) {
            throw new IllegalArgumentException("Invalid shared secret: " + ex.getMessage(), ex);
        }
    }

    /**
     * {@inheritDoc}
     */
    @Nonnull
    @Override
    public SecretKey generateSecret() {
        try {
            KeyGenerator generator = KeyGenerator.getInstance("Hmac" + this.algorithm.name());
            generator.init(80);
            return generator.generateKey();
        } catch (NoSuchAlgorithmException ex) {
            throw new UnsupportedOperationException("The specified algorithm is not supported by this Java VM implementation: " + ex.getMessage(), ex);
        }
    }

    /**
     * {@inheritDoc}
     */
    @Nonnull
    @Override
    public SecretKey parseCode(@Nonnull String code) {
        code = code.replace(" ", "").toUpperCase();

        byte[] key = (new Base32()).decode(code);
        return new SecretKeySpec(key, "Hmac" + this.algorithm.name());
    }

    /**
     * {@inheritDoc}
     */
    @Nonnull
    @Override
    public Algorithm getAlgorithm() {
        return this.algorithm;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public int getDigits() {
        return this.digits;
    }

    /**
     * {@inheritDoc}
     */
    @Nonnull
    @Override
    public String getIssuer() {
        return this.issuer;
    }
}
