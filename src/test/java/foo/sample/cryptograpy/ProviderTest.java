package foo.sample.cryptograpy;

import java.security.Provider;
import java.security.Security;
import java.security.Provider.Service;
import java.util.TreeSet;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Test;

public class ProviderTest {
	static {
		Security.addProvider(new BouncyCastleProvider());
	}

	@Test
	public void listsSupportedAlgorithms() {
		for (Provider provider : Security.getProviders()) {
			for (String key : provider.stringPropertyNames()) {
				System.out.println(provider.getName() + "\t" + key + "\t" + provider.getProperty(key));
			}
		}
		TreeSet<String> algs = new TreeSet<>();
		for (Provider provider : Security.getProviders()) {
			provider.getServices().stream().filter(s -> "Cipher".equals(s.getType())).map(Service::getAlgorithm)
					.forEach(algs::add);
		}
		algs.stream().forEach(System.out::println);
	}

}
