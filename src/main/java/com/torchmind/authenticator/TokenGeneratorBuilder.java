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

import java.time.Duration;

import edu.umd.cs.findbugs.annotations.NonNull;

/**
 * @author <a href="mailto:johannesd@torchmind.com">Johannes Donath</a>
 */
class TokenGeneratorBuilder implements TokenGenerator.Builder {
    private TokenGenerator.Algorithm algorithm = TokenGenerator.Algorithm.SHA1;
    private int digits = 6;
    private Duration period = Duration.ofSeconds(30);

    /**
     * {@inheritDoc}
     */
    @NonNull
    @Override
    public TokenGenerator.Algorithm algorithm() {
        return this.algorithm;
    }

    /**
     * {@inheritDoc}
     */
    @NonNull
    @Override
    public TokenGenerator.Builder algorithm(@NonNull TokenGenerator.Algorithm algorithm) {
        this.algorithm = algorithm;
        return this;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public int digits() {
        return this.digits;
    }

    /**
     * {@inheritDoc}
     */
    @NonNull
    @Override
    public TokenGenerator.Builder digits(int digits) {
        if (digits != 6 && digits != 8) {
            throw new IllegalArgumentException("Value must be either 6 or 8");
        }

        this.digits = digits;
        return this;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Duration period() {
        return this.period;
    }

    /**
     * {@inheritDoc}
     */
    @NonNull
    @Override
    public TokenGenerator.Builder period(@NonNull Duration period) {
        this.period = period;
        return this;
    }

    /**
     * {@inheritDoc}
     */
    @NonNull
    @Override
    public CounterTokenGenerator createCounterGenerator(@NonNull String issuer) {
        return new CounterTokenGenerator(this.algorithm, this.digits, issuer);
    }

    /**
     * {@inheritDoc}
     */
    @NonNull
    @Override
    public PeriodTokenGenerator createPeriodGenerator(@NonNull String issuer) {
        return new PeriodTokenGenerator(this.algorithm, this.digits, issuer, this.period);
    }
}
