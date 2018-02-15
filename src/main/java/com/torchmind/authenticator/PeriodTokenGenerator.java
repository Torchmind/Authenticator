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

import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLEncoder;
import java.nio.ByteBuffer;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;

import edu.umd.cs.findbugs.annotations.NonNull;
import javax.crypto.SecretKey;

/**
 * Provides a time based token generator implementation based on the TOTP specification.
 *
 * @author <a href="mailto:johannesd@torchmind.com">Johannes Donath</a>
 */
public class PeriodTokenGenerator extends AbstractTokenGenerator {
    private final Duration period;

    PeriodTokenGenerator(@NonNull Algorithm algorithm, int digits, @NonNull String issuer, @NonNull Duration period) {
        super(algorithm, digits, issuer);

        this.period = period;
    }

    /**
     * {@inheritDoc}
     */
    @NonNull
    @Override
    public URI buildUri(@NonNull SecretKey secretKey, @NonNull String accountName) {
        try {
            accountName = URLEncoder.encode(accountName, "UTF-8");
            String issuer = URLEncoder.encode(this.getIssuer(), "UTF-8");
            String secret = URLEncoder.encode(this.buildHandshakeCode(secretKey, false), "UTF-8");

            return new URI("otpauth", "totp", "/" + issuer + ":" + accountName, "secret=" + secret + "&issuer=" + issuer + "&period=" + this.period.getSeconds() + "&algorithm=" + this.getAlgorithm().name() + "&digits=" + this.getDigits(), null);
        } catch (UnsupportedEncodingException ex) {
            throw new UnsupportedOperationException("The specified encoding is not supported by this Java VM: " + ex.getMessage(), ex);
        } catch (URISyntaxException ex) {
            throw new IllegalArgumentException("One or more invalid parameters were passed: " + ex.getMessage(), ex);
        }
    }

    /**
     * Generates a code for the current timestamp.
     *
     * @param secretKey a secret key.
     * @return a code.
     */
    @NonNull
    public String generateCode(@NonNull SecretKey secretKey) {
        return this.generateCode(secretKey, Instant.now(Clock.systemUTC()));
    }

    /**
     * Generates a code for a specific timestamp.
     *
     * @param secretKey a secret key.
     * @param timestamp a timestamp.
     * @return a code.
     */
    @NonNull
    public String generateCode(@NonNull SecretKey secretKey, @NonNull Instant timestamp) {
        return this.generateCode(secretKey, ByteBuffer.allocate(8).putLong(timestamp.getEpochSecond() / this.period.getSeconds()).array());
    }

    /**
     * Validates the specified code against a set of codes within a certan range of periods.
     *
     * @param code      a code.
     * @param secretKey a secret key.
     * @param range     a range (amount of periods) to check in both directions.
     * @return true if the code is valid, false otherwise.
     */
    public boolean validateCode(@NonNull String code, @NonNull SecretKey secretKey, int range) {
        return this.validateCode(code, secretKey, Instant.now(), range);
    }

    /**
     * Validates the specified code against a set of codes within a certain range of periods.
     *
     * @param code      a code.
     * @param secretKey a secret key.
     * @param timestamp a timestamp.
     * @param range     a range (amount of periods) to check in both directions.
     * @return true if the code is valid, false otherwise.
     */
    public boolean validateCode(@NonNull String code, @NonNull SecretKey secretKey, @NonNull Instant timestamp, int range) {
        if (code.equals(this.generateCode(secretKey, timestamp))) {
            return true;
        }

        for (int i = 1; i <= range; ++i) {
            if (code.equals(this.generateCode(secretKey, timestamp.minus(this.period.getSeconds() * i, ChronoUnit.SECONDS)))) {
                return true;
            }

            if (code.equals(this.generateCode(secretKey, timestamp.plus(this.period.getSeconds() * i, ChronoUnit.SECONDS)))) {
                return true;
            }
        }

        return false;
    }
}
