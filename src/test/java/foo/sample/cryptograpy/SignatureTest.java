package foo.sample.cryptograpy;

import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

//see http://tutorials.jenkov.com/java-cryptography/index.html
public class SignatureTest {

	@Test
	public void verifiesRsaSignature() throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
		KeyPair keyPair = KeyManagmentTest.generateRsaKeyPair();
		byte[] data = "data to sign".getBytes();
		byte[] signature =  getRsaSignatureBytes(keyPair.getPrivate(), data);
		Assertions.assertTrue(verifyRsaSignature(keyPair.getPublic(), data, signature));
	}

	private byte[] getRsaSignatureBytes(PrivateKey privateKey, byte[] data)
			throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
		Signature signature = Signature.getInstance("SHA256WithRSA");
		signature.initSign(privateKey, SecureRandom.getInstanceStrong());
		signature.update(data);
		return signature.sign();
	}

	private boolean verifyRsaSignature(PublicKey publicKey, byte[] dataBytes, byte[] signatureBytes)
			throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
		Signature signature = Signature.getInstance("SHA256WithRSA");
		signature.initVerify(publicKey);
		signature.update(dataBytes);
		return signature.verify(signatureBytes);
	}
}
