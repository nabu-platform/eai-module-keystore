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
import java.util.ArrayList;
import java.util.Iterator;

import javax.xml.bind.JAXBException;

import be.nabu.libs.artifacts.api.Artifact;
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
import be.nabu.utils.security.resources.KeyStoreManagerConfiguration.KeyStoreConfiguration;
import be.nabu.utils.security.resources.ManagedKeyStoreImpl;
import be.nabu.utils.security.resources.ResourceConfigurationHandler;

// sub folders "certificates" and "keys"
public class KeyStoreArtifact implements Artifact {
	
	static {
		BCSecurityUtils.loadLibrary();
	}
	
	private ManagedKeyStoreImpl keystore;
	private ResourceContainer<?> directory;
	private String id;
	private KeyStoreConfiguration configuration;
	private Resource configurationResource;

	public KeyStoreArtifact(String id, ResourceContainer<?> directory) {
		this.directory = directory;
		this.id = id;
	}
	
	public void create(String password, StoreType type) throws IOException {
		configurationResource = directory.getChild("keystore.xml");
		if (configurationResource != null) {
			throw new IllegalArgumentException("Can not create the keystore, it already exists");
		}
		configurationResource = ((ManageableContainer<?>) directory).create("keystore.xml", "application/xml");
		configuration = new KeyStoreConfiguration();
		configuration.setAlias(getId());
		configuration.setPassword(password);
		configuration.setType(type == null ? StoreType.JKS : type);
		new ResourceConfigurationHandler(configurationResource).save(configuration);
	}
	
	public Resource getConfigurationResource() throws IOException {
		if (configurationResource == null) {
			configurationResource = directory.getChild("keystore.xml");
			if (configurationResource == null) {
				throw new IOException("The keystore was not properly initialized, there is no existing configuration");
			}
		}
		return configurationResource;
	}
	public KeyStoreConfiguration getConfiguration() throws IOException {
		if (configuration == null) {
			try {
				configuration = ResourceConfigurationHandler.unmarshal((ReadableResource) getConfigurationResource());
			}
			catch (JAXBException e) {
				throw new IOException(e);
			}
		}
		return configuration;
	}
	
	public void save(ResourceContainer<?> directory) throws IOException, KeyStoreException {
		ManagedKeyStoreImpl keystore = getKeyStore();
		String filename = "keystore." + getConfiguration().getType().name().toLowerCase();
		Resource target = directory.getChild(filename);
		if (target == null) {
			target = ((ManageableContainer<?>) directory).create(filename, getConfiguration().getType().getContentType());
		}
		keystore.save(target);
		target = directory.getChild("keystore.xml");
		if (target == null) {
			target = ((ManageableContainer<?>) directory).create("keystore.xml", "application/xml");
		}
		new ResourceConfigurationHandler(target).save(getConfiguration());
	}
	
	public ManagedKeyStoreImpl getKeyStore() throws IOException, KeyStoreException {
		if (keystore == null) {
			try {
				String filename = "keystore." + getConfiguration().getType().name().toLowerCase();
				Resource target = directory.getChild(filename);
				if (target == null) {
					keystore = new ManagedKeyStoreImpl(
						new ResourceConfigurationHandler((ReadableResource) getConfigurationResource()), 
						target, 
						getConfiguration(), 
						KeyStoreHandler.create(getConfiguration().getPassword(), getConfiguration().getType())
					);
				}
				else {
					ReadableContainer<ByteBuffer> input = new ResourceReadableContainer((ReadableResource) target);
					try {
						KeyStoreHandler handler = KeyStoreHandler.load(IOUtils.toInputStream(input), getConfiguration().getPassword(), getConfiguration().getType());
						keystore = new ManagedKeyStoreImpl(new ResourceConfigurationHandler((ReadableResource) getConfigurationResource()), target, getConfiguration(), handler);
					}
					finally {
						input.close();
					}
				}
				keystore.setSaveOnChange(false);
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
		return keystore;
	}
	
	@Override
	public String getId() {
		return id;
	}

	public ResourceContainer<?> getDirectory() {
		return directory;
	}

	public String getContentType() {
		return Resource.CONTENT_TYPE_DIRECTORY;
	}

	public String getName() {
		return "artifact";
	}

	public ResourceContainer<?> getParent() {
		return null;
	}

	public Iterator<Resource> iterator() {
		return new ArrayList<Resource>().iterator();
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
