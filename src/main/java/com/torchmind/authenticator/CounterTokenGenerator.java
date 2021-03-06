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

import edu.umd.cs.findbugs.annotations.NonNull;
import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLEncoder;
import java.nio.ByteBuffer;
import javax.crypto.SecretKey;

/**
 * Provides a counter based token generator implementation based on the HOTP specification.
 *
 * @author <a href="mailto:johannesd@torchmind.com">Johannes Donath</a>
 */
public class CounterTokenGenerator extends AbstractTokenGenerator {

  CounterTokenGenerator(@NonNull Algorithm algorithm, int digits, @NonNull String issuer) {
    super(algorithm, digits, issuer);
  }

  /**
   * {@inheritDoc}
   */
  @NonNull
  @Override
  public URI buildUri(@NonNull SecretKey secretKey, @NonNull String accountName) {
    return this.buildUri(secretKey, accountName, 1);
  }

  /**
   * Builds a new handshake URI.
   *
   * @param secretKey a secret key.
   * @param accountName an account name.
   * @param counter an initial counter value.
   * @return a URI.
   */
  @NonNull
  public URI buildUri(@NonNull SecretKey secretKey, @NonNull String accountName, int counter) {
    try {
      accountName = URLEncoder.encode(accountName, "UTF-8");
      String issuer = URLEncoder.encode(this.getIssuer(), "UTF-8");
      String secret = URLEncoder.encode(this.buildHandshakeCode(secretKey, false), "UTF-8");

      return new URI("otpauth", "hotp", "/" + issuer + ":" + accountName,
          "secret=" + secret + "&issuer=" + issuer + "&counter=" + counter + "&algorithm=" + this
              .getAlgorithm().name() + "&digits=" + this.getDigits(), null);
    } catch (UnsupportedEncodingException ex) {
      throw new UnsupportedOperationException(
          "The specified encoding is not supported by this Java VM: " + ex.getMessage(), ex);
    } catch (URISyntaxException ex) {
      throw new IllegalArgumentException(
          "One or more invalid parameters were passed: " + ex.getMessage(), ex);
    }
  }

  /**
   * Generates a code using the specified secret key and counter value.
   *
   * @param secretKey a secret key.
   * @param counter a counter.
   * @return a code.
   * @throws IllegalArgumentException when the supplied shared secret is incompatible with the
   * chosen algorithm.
   * @throws UnsupportedOperationException when the Java VM does not support the chosen hashing
   * algorithm.
   */
  @NonNull
  public String generateCode(@NonNull SecretKey secretKey, long counter) {
    return this.generateCode(secretKey, ByteBuffer.allocate(8).putLong(counter).array());
  }
}
