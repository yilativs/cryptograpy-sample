package foo.sample.cryptograpy;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public class CipherTest {
	static {
		Security.addProvider(new BouncyCastleProvider());
	}

	@Test
	public void encrypsAndDecrypsWithAES() throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
		SecretKey secretKey = KeyManagmentTest.generateAesSecretKey();
		Cipher encryptionCipher = Cipher.getInstance(secretKey.getAlgorithm()); 
		encryptionCipher.init(Cipher.ENCRYPT_MODE, secretKey);
		encryptionCipher.update("test".getBytes());
		byte[] encryptedBytes = encryptionCipher.doFinal(); 
		
		Cipher decriptionCipher = Cipher.getInstance(secretKey.getAlgorithm());
		decriptionCipher.init(Cipher.DECRYPT_MODE, secretKey);
		decriptionCipher.update(encryptedBytes);
		byte[] decryptedBytes = decriptionCipher.doFinal();
		Assertions.assertArrayEquals("test".getBytes(), decryptedBytes);
	}
	
	@Test
	public void encrypsAndDecrypsWithRSA() throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
		KeyPair keyPair = KeyManagmentTest.generateRsaKeyPair();
		Cipher encryptionCipher = Cipher.getInstance(keyPair.getPrivate().getAlgorithm()); 
		encryptionCipher.init(Cipher.ENCRYPT_MODE, keyPair.getPrivate());
		encryptionCipher.update("test".getBytes());
		byte[] encryptedBytes = encryptionCipher.doFinal(); 
		
		Cipher decriptionCipher = Cipher.getInstance(keyPair.getPrivate().getAlgorithm());
		decriptionCipher.init(Cipher.DECRYPT_MODE, keyPair.getPublic());
		decriptionCipher.update(encryptedBytes);
		byte[] decryptedBytes = decriptionCipher.doFinal();
		Assertions.assertArrayEquals("test".getBytes(), decryptedBytes);
	}
	
	@Test
	public void encrypsAndDecrypsWithGost() throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, NoSuchProviderException {
		KeyPair keyPair = KeyManagmentTest.generateGost12KeyPair();
		Cipher encryptionCipher = Cipher.getInstance(keyPair.getPrivate().getAlgorithm(),"BC"); 
		encryptionCipher.init(Cipher.ENCRYPT_MODE, keyPair.getPrivate());
		encryptionCipher.update("test".getBytes());
		byte[] encryptedBytes = encryptionCipher.doFinal(); 
		
		Cipher decriptionCipher = Cipher.getInstance(keyPair.getPrivate().getAlgorithm(),"BC");
		decriptionCipher.init(Cipher.DECRYPT_MODE, keyPair.getPublic());
		decriptionCipher.update(encryptedBytes);
		byte[] decryptedBytes = decriptionCipher.doFinal();
		Assertions.assertArrayEquals("test".getBytes(), decryptedBytes);
	}

}
