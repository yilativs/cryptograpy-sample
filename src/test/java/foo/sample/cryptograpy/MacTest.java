package foo.sample.cryptograpy;

import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

//see
//http://tutorials.jenkov.com/java-cryptography/mac.html
public class MacTest {

	private static final String HMAC_SHA256 = "HmacSHA256";

	@Test
	public void createsAndVerifiesHmac() throws NoSuchAlgorithmException, InvalidKeyException {
		KeyGenerator generator = KeyGenerator.getInstance("AES");
		generator.init(256);
		SecretKey key = generator.generateKey();

		Mac mac1 = Mac.getInstance(HMAC_SHA256);
		mac1.init(key);

		mac1.update("012".getBytes(StandardCharsets.UTF_8));
		mac1.update("456".getBytes(StandardCharsets.UTF_8));
		byte[] stepByStepMac = mac1.doFinal();

		Mac mac2 = Mac.getInstance(HMAC_SHA256);
		mac2.init(key);

		byte[] allAtOnceMac = mac2.doFinal("012456".getBytes(StandardCharsets.UTF_8));
		Assertions.assertArrayEquals(allAtOnceMac, stepByStepMac);
		}

}
