/*
* Copyright (C) 2016 Alexander Verbruggen
*
* This program is free software: you can redistribute it and/or modify
* it under the terms of the GNU Lesser General Public License as published by
* the Free Software Foundation, either version 3 of the License, or
* (at your option) any later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
* GNU Lesser General Public License for more details.
*
* You should have received a copy of the GNU Lesser General Public License
* along with this program. If not, see <https://www.gnu.org/licenses/>.
*/

package nabu.misc.keystore;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.InvalidKeyException;
import java.security.Key;
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
import be.nabu.utils.security.MacAlgorithm;
import be.nabu.utils.security.SecurityUtils;
import be.nabu.utils.security.api.KeyStoreEntryType;

@WebService
public class Services {
	private ExecutionContext executionContext;
	
	// this is not serializable
	// should standardize on "bytes" if we ever need this, the nabu.utils.Security.mac service expects a byte array as input for key
//	public Object getSecretKey(@WebParam(name = "keystoreId") String keystoreId, @NotNull @WebParam(name = "keyAlias") String keyAlias) throws KeyStoreException, IOException {
//		KeyStoreArtifact keystore = executionContext.getServiceContext().getResolver(KeyStoreArtifact.class).resolve(keystoreId);
//		if (keystore == null) {
//			throw new IllegalArgumentException("No keystore found");
//		}
//		SecretKey secretKey = keystore.getKeyStore().getSecretKey(keyAlias);
//		return secretKey;
//	}
	
	@WebResult(name = "bytes")
	public InputStream encrypt(@WebParam(name = "stream") InputStream input, @NotNull @WebParam(name = "keystoreId") String keystoreId, @NotNull @WebParam(name = "keyAlias") String keyAlias) throws KeyStoreException, IOException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
		return processSymmetric(input, keystoreId, keyAlias, Cipher.ENCRYPT_MODE);
	}
	
	@WebResult(name = "bytes")
	public InputStream decrypt(@WebParam(name = "stream") InputStream input, @NotNull @WebParam(name = "keystoreId") String keystoreId, @NotNull @WebParam(name = "keyAlias") String keyAlias) throws KeyStoreException, IOException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
		return processSymmetric(input, keystoreId, keyAlias, Cipher.DECRYPT_MODE);
	}

	@WebResult(name = "mac")
	public java.lang.String mac(@WebParam(name = "stream") InputStream content, @NotNull @WebParam(name = "keystoreId") String keystoreId, @NotNull @WebParam(name = "keyAlias") String keyAlias, @WebParam(name = "algorithm") MacAlgorithm algorithm) throws NoSuchAlgorithmException, IOException, InvalidKeyException, IllegalStateException, KeyStoreException {
		KeyStoreArtifact keystore = executionContext.getServiceContext().getResolver(KeyStoreArtifact.class).resolve(keystoreId);
		if (keystore == null) {
			throw new IllegalArgumentException("No keystore found");
		}
		SecretKey secretKey = keystore.getKeyStore().getSecretKey(keyAlias);
		return SecurityUtils.encodeMac(secretKey, content, algorithm.name());
	}
	
	@WebResult(name = "key")
	public Key getKey(@NotNull @WebParam(name = "keystoreId") String keystoreId, @NotNull @WebParam(name = "keyAlias") String alias) throws KeyStoreException, IOException {
		KeyStoreArtifact keystore = executionContext.getServiceContext().getResolver(KeyStoreArtifact.class).resolve(keystoreId);
		if (keystore == null) {
			throw new IllegalArgumentException("No keystore found");
		}
		KeyStoreEntryType entryType = keystore.getKeyStore().getEntryType(alias);
		switch (entryType) {
			case PRIVATE_KEY:
				return keystore.getKeyStore().getPrivateKey(alias);
			case SECRET_KEY:
				return keystore.getKeyStore().getSecretKey(alias);
			default:
				throw new RuntimeException("Invalid alias: " + alias);
		}
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
