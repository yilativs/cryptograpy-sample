package foo.sample.cryptograpy;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.OutputStream;
import java.io.Writer;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.Date;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.X509Principal;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.x509.X509V3CertificateGenerator;
import org.junit.jupiter.api.Test;

//http://www.bouncycastle.org/documentation.html
public class KeyManagmentTest {
	static {
		Security.addProvider(new BouncyCastleProvider());
	}

	// we will use it for both key store and alias
	private static final char[] PASSWORD = "secretPassword".toCharArray();

	@Test
	public void manageKeys() throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException,
			InvalidAlgorithmParameterException, InvalidKeyException, IllegalStateException, NoSuchProviderException,
			SignatureException {
		KeyPair rsaKeyPair = generateRsaKeyPair();
		storeKeysInFiles(rsaKeyPair);
		saveEntryInNewKeyStore("rsaKeyStore", rsaKeyPair, generatSelfSignedRsaCertificateWithBC(rsaKeyPair),
				"selfSignedTest");

		KeyPair gostKeyPair = generateGost12KeyPair();
		storeKeysInFiles(gostKeyPair);
		saveEntryInNewKeyStore("gostKeyStore", gostKeyPair, generatSelfSignedGostCertificateWithBC(gostKeyPair),
				"selfSignedTest");

		SecretKey secretKey = generateAesSecretKey();
		saveEntryInNewKeyStore("secretKeyStore", secretKey, "secretKeyTest");

	}

	// https://www.novixys.com/blog/how-to-generate-rsa-keys-java/
	private void storeKeysInFiles(KeyPair keyPair) throws IOException, FileNotFoundException, KeyStoreException,
			NoSuchAlgorithmException, CertificateException {
		// storing private key in pkcs8
		try (OutputStream out = new FileOutputStream("privateRsaKey-pkcs8.key")) {
			System.out.println(keyPair.getPrivate().getFormat());// prints in PKCS#8
			out.write(keyPair.getPrivate().getEncoded());// stores in PKCS#8
		}

		try (Writer writer = new FileWriter(new File("privateRsaKey-base64.key"))) {
			writer.write("-----BEGIN RSA PRIVATE KEY-----\n");
			writer.write(Base64.getEncoder().encodeToString(keyPair.getPrivate().getEncoded()));
			writer.write("\n-----END RSA PRIVATE KEY-----\n");
		}

		// storing public key in x.509
		try (OutputStream out = new FileOutputStream("publicRsa-x509.pub")) {
			System.out.println(keyPair.getPublic().getFormat());// prints in X.509
			out.write(keyPair.getPublic().getEncoded());// stores in in X.509
		}

		try (Writer writer = new FileWriter(new File("publiceRsaKey-base64.key"))) {
			writer.write("-----BEGIN RSA PUBLIC KEY-----\n");
			writer.write(Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded()));
			writer.write("\n-----END RSA PUBLIC KEY-----\n");
		}

	}

	static SecretKey generateAesSecretKey() throws NoSuchAlgorithmException {
		KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
		keyGenerator.init(256);//in java it is number of BITS (not bytes)
		return keyGenerator.generateKey();
	}

	static KeyPair generateRsaKeyPair() throws NoSuchAlgorithmException {
		KeyPairGenerator keyPairGeneratorGenerator = KeyPairGenerator.getInstance("RSA");
		// exponent must be >=3 - though this makes key generation really slow
//		keyPairGeneratorGenerator.initialize(new RSAKeyGenParameterSpec(2048, new BigInteger("3")),	SecureRandom.getInstanceStrong());
		keyPairGeneratorGenerator.initialize(2048);
		return keyPairGeneratorGenerator.generateKeyPair();// this may take long
	}

	static KeyPair generateGostKeyPair()
			throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
		KeyPairGenerator keyPairGeneratorGenerator = KeyPairGenerator.getInstance("ECGOST3410-12", "BC");
		// exponent must be >=3 - though this makes key generation really slow
		keyPairGeneratorGenerator.initialize(new ECGenParameterSpec("GostR3410-2012-CryptoPro-A"));
		return keyPairGeneratorGenerator.generateKeyPair();// this may take long
	}

	public static KeyPair generateGost12KeyPair()
			throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, NoSuchProviderException {
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("ECGOST3410-2012", "BC");
//		keyPairGenerator.initialize(ECNamedCurveTable.getParameterSpec("prime256v1"), new SecureRandom());//doesn't work
		keyPairGenerator.initialize(ECNamedCurveTable.getParameterSpec("GostR3410-2001-CryptoPro-A"),
				new SecureRandom());
		return keyPairGenerator.generateKeyPair();
	}

	// see
	// http://www.bouncycastle.org/wiki/display/JA1/X.509+Public+Key+Certificate+and+Certification+Request+Generation
	public X509Certificate generatSelfSignedRsaCertificateWithBC(KeyPair keyPair)
			throws CertificateEncodingException, InvalidKeyException, IllegalStateException, NoSuchProviderException,
			NoSuchAlgorithmException, SignatureException {
		X509V3CertificateGenerator cert = new X509V3CertificateGenerator();
		cert.setSerialNumber(BigInteger.valueOf(1)); // or generate a random number
		cert.setSubjectDN(new X509Principal("CN=localhost")); // see examples to add O,OU etc
		cert.setIssuerDN(new X509Principal("CN=localhost")); // same since it is self-signed
		cert.setPublicKey(keyPair.getPublic());
		cert.setNotBefore(new Date());
		cert.setNotAfter(Date.from(LocalDateTime.of(2030, 1, 1, 0, 0).toInstant(ZoneOffset.UTC)));
		cert.setSignatureAlgorithm("SHA1WithRSAEncryption");
		PrivateKey signingKey = keyPair.getPrivate();
		return cert.generate(signingKey, "BC");
	}

	// see
	// http://www.bouncycastle.org/wiki/display/JA1/X.509+Public+Key+Certificate+and+Certification+Request+Generation
	public X509Certificate generatSelfSignedGostCertificateWithBC(KeyPair keyPair)
			throws CertificateEncodingException, InvalidKeyException, IllegalStateException, NoSuchProviderException,
			NoSuchAlgorithmException, SignatureException {
		X509V3CertificateGenerator cert = new X509V3CertificateGenerator();
		cert.setSerialNumber(BigInteger.valueOf(1)); // or generate a random number
		cert.setSubjectDN(new X509Principal("CN=localhost")); // see examples to add O,OU etc
		cert.setIssuerDN(new X509Principal("CN=localhost")); // same since it is self-signed
		cert.setPublicKey(keyPair.getPublic());
		cert.setNotBefore(new Date());
		cert.setNotAfter(Date.from(LocalDateTime.of(2030, 1, 1, 0, 0).toInstant(ZoneOffset.UTC)));
		cert.setSignatureAlgorithm("GOST3411WITHECGOST3410");
		PrivateKey signingKey = keyPair.getPrivate();
		return cert.generate(signingKey, "BC");
	}

	// see
	// https://stackoverflow.com/questions/13894699/java-how-to-store-a-key-in-keystore
	private KeyStore saveEntryInNewKeyStore(String filePath, KeyPair keyPair, X509Certificate certificate, String alias)
			throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException {
		KeyStore keyStore = KeyStore.getInstance("JCEKS");// never use JKS - it is weak
		keyStore.load(null, null);
		try (FileOutputStream fos = new FileOutputStream(filePath)) {
			Certificate[] certificateChain = { certificate };
			keyStore.setKeyEntry(alias, (Key) keyPair.getPrivate(), PASSWORD, certificateChain);
			// saves KeyStore into a file
			keyStore.store(fos, PASSWORD);
		}
		return keyStore;
	}

	// https://www.tutorialspoint.com/java_cryptography/java_cryptography_storing_keys.htm
	private KeyStore saveEntryInNewKeyStore(String filePath, SecretKey secretKey, String alias)
			throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException {
		KeyStore keyStore = KeyStore.getInstance("JCEKS");// never use JKS - it is weak
		keyStore.load(null, null);
		try (FileOutputStream fos = new FileOutputStream(filePath)) {
			keyStore.setEntry(alias, new KeyStore.SecretKeyEntry(secretKey), new KeyStore.PasswordProtection(PASSWORD));
			// saves KeyStore into a file
			keyStore.store(fos, PASSWORD);
		}
		return keyStore;
	}

}
