/**
 * Provides a modern multi factor authentication token implementation for the HOTP and TOTP protocol
 * specifications.
 *
 * @author <a href="mailto:johannesd@torchmind.com">Johannes Donath</a>
 */
module com.torchmind.authenticator {
  exports com.torchmind.authenticator;

  requires static com.github.spotbugs.annotations;
  requires org.apache.commons.codec;
}
