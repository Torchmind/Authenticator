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
