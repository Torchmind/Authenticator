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

import javax.annotation.Nonnegative;
import javax.annotation.Nonnull;
import javax.annotation.concurrent.NotThreadSafe;

/**
 * @author <a href="mailto:johannesd@torchmind.com">Johannes Donath</a>
 */
@NotThreadSafe
class TokenGeneratorBuilder implements TokenGenerator.Builder {
    private TokenGenerator.Algorithm algorithm = TokenGenerator.Algorithm.SHA1;
    private int digits = 6;
    private Duration period = Duration.ofSeconds(30);

    /**
     * {@inheritDoc}
     */
    @Nonnull
    @Override
    public TokenGenerator.Algorithm algorithm() {
        return this.algorithm;
    }

    /**
     * {@inheritDoc}
     */
    @Nonnull
    @Override
    public TokenGenerator.Builder algorithm(@Nonnull TokenGenerator.Algorithm algorithm) {
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
    @Nonnull
    @Override
    public TokenGenerator.Builder digits(@Nonnegative int digits) {
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
    @Nonnull
    @Override
    public TokenGenerator.Builder period(@Nonnegative Duration period) {
        this.period = period;
        return this;
    }

    /**
     * {@inheritDoc}
     */
    @Nonnull
    @Override
    public CounterTokenGenerator createCounterGenerator(@Nonnull String issuer) {
        return new CounterTokenGenerator(this.algorithm, this.digits, issuer);
    }

    /**
     * {@inheritDoc}
     */
    @Nonnull
    @Override
    public PeriodTokenGenerator createPeriodGenerator(@Nonnull String issuer) {
        return new PeriodTokenGenerator(this.algorithm, this.digits, issuer, this.period);
    }
}
