package nabu.misc.keystore;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.InvalidKeyException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.jws.WebParam;
import javax.jws.WebResult;
import javax.jws.WebService;
import javax.validation.constraints.NotNull;

import be.nabu.eai.module.keystore.KeyStoreArtifact;
import be.nabu.libs.services.api.ExecutionContext;

@WebService
public class Services {
	private ExecutionContext executionContext;
	
	@WebResult(name = "bytes")
	public InputStream encrypt(@WebParam(name = "stream") InputStream input, @NotNull @WebParam(name = "keystoreId") String keystoreId, @NotNull @WebParam(name = "keyAlias") String keyAlias) throws KeyStoreException, IOException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
		return processSymmetric(input, keystoreId, keyAlias, Cipher.ENCRYPT_MODE);
	}
	
	@WebResult(name = "bytes")
	public InputStream decrypt(@WebParam(name = "stream") InputStream input, @NotNull @WebParam(name = "keystoreId") String keystoreId, @NotNull @WebParam(name = "keyAlias") String keyAlias) throws KeyStoreException, IOException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
		return processSymmetric(input, keystoreId, keyAlias, Cipher.DECRYPT_MODE);
	}

	private InputStream processSymmetric(InputStream input, String keystoreId, String keyAlias, Integer mode) throws KeyStoreException, IOException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
		if (input == null) {
			return null;
		}
		KeyStoreArtifact keystore = executionContext.getServiceContext().getResolver(KeyStoreArtifact.class).resolve(keystoreId);
		if (keystore == null) {
			throw new IllegalArgumentException("No keystore found");
		}
		SecretKey secretKey = keystore.getKeyStore().getSecretKey(keyAlias);
		Cipher cipher = Cipher.getInstance(secretKey.getAlgorithm());
		cipher.init(mode, secretKey);
		int read = 0;
		byte [] buffer = new byte[8092];
		ByteArrayOutputStream output = new ByteArrayOutputStream();
		while ((read = input.read(buffer)) >= 0) {
			output.write(cipher.update(buffer, 0, read));
		}
		output.write(cipher.doFinal());
		return new ByteArrayInputStream(output.toByteArray());
	}
	
}
