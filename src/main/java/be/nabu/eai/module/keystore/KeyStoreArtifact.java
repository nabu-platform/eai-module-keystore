package be.nabu.eai.module.keystore;

import java.io.IOException;
import java.io.StringWriter;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.UUID;

import be.nabu.eai.module.keystore.persistance.KeyStorePersistanceArtifact;
import be.nabu.eai.repository.api.Repository;
import be.nabu.eai.repository.artifacts.jaxb.JAXBArtifact;
import be.nabu.libs.resources.ResourceReadableContainer;
import be.nabu.libs.resources.api.ManageableContainer;
import be.nabu.libs.resources.api.ReadableResource;
import be.nabu.libs.resources.api.Resource;
import be.nabu.libs.resources.api.ResourceContainer;
import be.nabu.libs.resources.memory.MemoryItem;
import be.nabu.utils.io.IOUtils;
import be.nabu.utils.io.api.ByteBuffer;
import be.nabu.utils.io.api.ReadableContainer;
import be.nabu.utils.io.api.WritableContainer;
import be.nabu.utils.security.BCSecurityUtils;
import be.nabu.utils.security.KeyStoreHandler;
import be.nabu.utils.security.StoreType;
import be.nabu.utils.security.api.ManagedKeyStore;
import be.nabu.utils.security.basic.BasicManagedKeyStore;
import be.nabu.utils.security.resources.ManagedKeyStoreImpl;
import be.nabu.utils.security.resources.ResourceConfigurationHandler;

// sub folders "certificates" and "keys"
public class KeyStoreArtifact extends JAXBArtifact<KeyStoreArtifactConfiguration> {

	static {
		BCSecurityUtils.loadLibrary();
	}
	
	private ManagedKeyStore keystore;

	public KeyStoreArtifact(String id, ResourceContainer<?> directory, Repository repository) {
		super(id, directory, repository, "keystore.xml", KeyStoreArtifactConfiguration.class);
	}
	
	public void create(String password, KeyStorePersistanceArtifact persister) throws IOException {
		KeyStoreArtifactConfiguration configuration = getConfig();
		configuration.setAlias(getId());
		configuration.setPassword(password == null ? UUID.randomUUID().toString().replace("-", "") : password);
		configuration.setPersister(persister);
	}
	
	public void create(String password, StoreType type) throws IOException {
		KeyStoreArtifactConfiguration configuration = getConfig();
		configuration.setAlias(getId());
		configuration.setPassword(password == null ? UUID.randomUUID().toString().replace("-", "") : password);
		configuration.setType(type == null ? StoreType.JKS : type);
	}
	
	private Resource getConfigurationResource() throws IOException {
		return getDirectory().getChild("keystore.xml");
	}
	
	@Override
	public void save(ResourceContainer<?> directory) {
		try {
			super.save(directory);
			ManagedKeyStore keystore = getKeyStore();
			// only these are actually persisted
			if (keystore instanceof ManagedKeyStoreImpl) {
				String filename = "keystore." + getConfiguration().getType().name().toLowerCase();
				Resource target = directory.getChild(filename);
				if (target == null) {
					target = ((ManageableContainer<?>) directory).create(filename, getConfiguration().getType().getContentType());
				}
				// the resource version actually stores the keystore on disk so needs to persist it to the directory as well
				// the basic one uses an external persistance manager
				if (keystore instanceof ManagedKeyStoreImpl) {
					((ManagedKeyStoreImpl) keystore).save(target);
				}
			}
		}
		catch (Exception e) {
			throw new RuntimeException(e);
		}
	}
	
	public ManagedKeyStore getKeyStore() throws IOException, KeyStoreException {
		if (keystore == null) {
			if (getConfig().getPersister() != null) {
				keystore = new BasicManagedKeyStore(getConfig().getPersister().getManager(), getId(), getConfig().getPassword());
			}
			else {
				try {
					String filename = "keystore." + getConfiguration().getType().name().toLowerCase();
					Resource target = getDirectory().getChild(filename);
					if (target == null) {
						target = ((ManageableContainer<?>) getDirectory()).create(filename, getConfiguration().getType().getContentType());
						keystore = new ManagedKeyStoreImpl(
							new ResourceConfigurationHandler((ReadableResource) getConfigurationResource(), KeyStoreArtifactConfiguration.class), 
							target, 
							getConfiguration(), 
							KeyStoreHandler.create(getConfiguration().getPassword(), getConfiguration().getType())
						);
					}
					else {
						ReadableContainer<ByteBuffer> input = new ResourceReadableContainer((ReadableResource) target);
						try {
							KeyStoreHandler handler = KeyStoreHandler.load(IOUtils.toInputStream(input), getConfiguration().getPassword(), getConfiguration().getType());
							keystore = new ManagedKeyStoreImpl(new ResourceConfigurationHandler((ReadableResource) getConfigurationResource(), KeyStoreArtifactConfiguration.class), target, getConfiguration(), handler);
						}
						finally {
							input.close();
						}
					}
					((ManagedKeyStoreImpl) keystore).setSaveOnChange(false);
				}
				catch (NoSuchAlgorithmException e) {
					throw new KeyStoreException(e);
				}
				catch (CertificateException e) {
					throw new KeyStoreException(e);
				}
				catch (NoSuchProviderException e) {
					throw new KeyStoreException(e);
				}
			}
		}
		return keystore;
	}
	
	private Resource buildItem(String name, byte [] content) {
		MemoryItem item = new MemoryItem(name);
		WritableContainer<ByteBuffer> writable = item.getWritable();
		try {
			writable.write(IOUtils.wrap(content, true));
			writable.close();
		}
		catch (Exception e) {
			throw new RuntimeException(e);
		}
		return item;
	}
	
	public Resource getChild(String name) {
		try {
			String[] parts = name.split(":");
			// we want at least two parts to each name: the alias and the format you want it as
			// additional parts can act as a modifier (e.g. a password)
			if (parts.length < 2) {
				return null;
			}
			if (parts[1].equalsIgnoreCase("ssh") || parts[1].equalsIgnoreCase("ssh-priv")) {
				PrivateKey privateKey = getKeyStore().getPrivateKey(parts[0]);
				StringWriter writer = new StringWriter();
				BCSecurityUtils.writeSSHKey(writer, privateKey, parts.length == 2 ? null : parts[2]);
				return buildItem(name, writer.toString().getBytes());
			}
			else if (parts[1].equalsIgnoreCase("ssh-pub")) {
				X509Certificate[] chain = getKeyStore().getChain(parts[0]);
				PublicKey publicKey = chain[0].getPublicKey();
				StringWriter writer = new StringWriter();
				BCSecurityUtils.writeSSHKey(writer, publicKey);
				return buildItem(name, writer.toString().getBytes());
			}
		}
		catch (Exception e) {
			throw new RuntimeException(e);
		}
		return null;
	}
}
