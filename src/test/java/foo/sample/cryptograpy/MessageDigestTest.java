package foo.sample.cryptograpy;

import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

//see 
//http://tutorials.jenkov.com/java-cryptography/index.html 
//https://docs.oracle.com/en/java/javase/11/docs/api/java.base/java/security/MessageDigest.html
public class MessageDigestTest {
	private static final String SHA_256 = "SHA-256";

	@Test
	public void createsAndValidatesMessageDigest() throws UnsupportedEncodingException, NoSuchAlgorithmException {
		MessageDigest messageDigest = MessageDigest.getInstance(SHA_256);
		messageDigest.update("012".getBytes(StandardCharsets.UTF_8));
		messageDigest.update("456".getBytes(StandardCharsets.UTF_8));
		byte[] stepByStepDigest = messageDigest.digest();

		byte[] allAtOnceDigest = MessageDigest.getInstance(SHA_256).digest("012456".getBytes(StandardCharsets.UTF_8));
		Assertions.assertArrayEquals(allAtOnceDigest, stepByStepDigest);
	}

}
