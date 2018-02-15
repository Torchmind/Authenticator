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

import java.net.URI;
import java.time.Duration;

import edu.umd.cs.findbugs.annotations.NonNull;
import javax.crypto.SecretKey;

/**
 * Provides a base interface which is shared by all HOTP and TOTP authenticator implementations.
 *
 * <strong>Note:</strong> Implementations of this type are required to be thread safe and may thus
 * be safely shared across contexts in web applications.
 *
 * @author <a href="mailto:johannesd@torchmind.com">Johannes Donath</a>
 */
public interface TokenGenerator {

    /**
     * Creates a new token generator builder.
     *
     * @return a new builder.
     */
    @NonNull
    static Builder builder() {
        return new TokenGeneratorBuilder();
    }

    /**
     * Builds the handshake URI for a certain user using a pre-generated secret key and a
     * descriptive account name.
     *
     * <strong>Note:</strong> If the specialized generator implementation provides further
     * properties, default values are assumed for them unless specified with one of the overloads of
     * this method.
     *
     * @param secretKey   a secret key.
     * @param accountName an account name.
     * @return a URI.
     *
     * @throws IllegalArgumentException      when one or more specified arguments are invalid.
     * @throws UnsupportedOperationException when the generator requires additional parameters or
     *                                       the Java VM implementation does not support the default
     *                                       encoding.
     */
    @NonNull
    URI buildUri(@NonNull SecretKey secretKey, @NonNull String accountName);

    /**
     * Generates a human readable code which serves as a replacement for the URI (which is usually
     * presented to the user as a QR code).
     *
     * @param secretKey a shared secret.
     * @return a human readable code.
     *
     * @see #buildHandshakeCode(SecretKey, boolean) for a version of this method which allows to
     * create codes without special formatting such as spaces.
     */
    @NonNull
    default String buildHandshakeCode(@NonNull SecretKey secretKey) {
        return this.buildHandshakeCode(secretKey, true);
    }

    /**
     * Generates an optionally human readable code which serves as a replacement for the URI (which
     * is usually presented to the user as a QR code).
     *
     * @param secretKey     a shared secret.
     * @param humanReadable when true adds spaces and changes casing to improve readability.
     * @return a code.
     */
    @NonNull
    String buildHandshakeCode(@NonNull SecretKey secretKey, boolean humanReadable);

    /**
     * Generates a new shared secret for use with this token generator.
     *
     * @return a secret.
     *
     * @throws UnsupportedOperationException when the current Java VM implementation does not
     *                                       support the chosen hashing algorithm or HMAC itself.
     */
    @NonNull
    SecretKey generateSecret();

    /**
     * Retrieves the selected hashing algorithm.
     *
     * @return an algorithm.
     */
    @NonNull
    Algorithm getAlgorithm();

    /**
     * Returns the amount of digits to generate (may only be 6 or 8).
     *
     * @return an amount of digits.
     */
    int getDigits();

    /**
     * Retrieves a human readable issuer which is to be displayed in the client.
     *
     * @return an issuer name.
     */
    @NonNull
    String getIssuer();

    /**
     * Parses a human readable or URI encoded shared secret.
     *
     * @param code a code.
     * @return a shared secret.
     */
    @NonNull
    SecretKey parseCode(@NonNull String code);

    /**
     * Provides a list of valid hashing algorithms to be used in combination with HMAC.
     */
    enum Algorithm {
        SHA1,
        SHA256,
        SHA512
    }

    /**
     * Provides a factory for the creation of token generator instances.
     */
    interface Builder {

        /**
         * Retrieves the currently configured hashing algorithm (defaults to {@link
         * Algorithm#SHA1}).
         *
         * @return an algorithm.
         */
        @NonNull
        Algorithm algorithm();

        /**
         * Sets the target hashing algorithm.
         *
         * <strong>Note:</strong> This parameter is ignored by the Google Authenticator
         * implementation and should thus be left on its default value if compatibility with the
         * Google implementation is expected.
         *
         * @param algorithm an algorithm.
         * @return a reference to this builder instance.
         */
        @NonNull
        Builder algorithm(@NonNull Algorithm algorithm);

        /**
         * Retrieves the currently configured amount of digits (defaults to 6).
         *
         * @return an amount of digits (either 6 or 8).
         */
        int digits();

        /**
         * Sets the target digit amount (either 6 or 8).
         *
         * <strong>Note:</strong> This parameter is ignored by the Google Authenticator
         * implementation and should thus be left on its default value if compatibility with the
         * Google implementation is expected.
         *
         * @param digits an amount of digits.
         * @return a reference to this builder instance.
         *
         * @throws IllegalArgumentException when the supplied amount of digits isn't 6 or 8.
         */
        @NonNull
        Builder digits(int digits);

        /**
         * Retrieves the currently configured period of time a key is valid for.
         *
         * @return a period.
         */
        Duration period();

        /**
         * Sets the period of time a key is valid for (only used when creating a TOTP based
         * generator).
         *
         * <strong>Note:</strong> This parameter is ignored by the Google Authenticator
         * implementation and should thus be left on its default value if compatibility with the
         * Google implementation is expected.
         *
         * @param period the amount of time a key is considered valid for.
         * @return a reference to this builder.
         */
        @NonNull
        Builder period(Duration period);

        /**
         * Creates a counter based generator (using the HOTP specification).
         *
         * @param issuer an issuer name.
         * @return a generator.
         */
        @NonNull
        CounterTokenGenerator createCounterGenerator(@NonNull String issuer);

        /**
         * Creates a period (time) based generator (using the TOTP specification).
         *
         * @param issuer an issuer name.
         * @return a generator.
         */
        @NonNull
        PeriodTokenGenerator createPeriodGenerator(@NonNull String issuer);
    }
}
