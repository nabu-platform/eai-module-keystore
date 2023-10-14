package be.nabu.eai.module.keystore;

import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.adapters.XmlJavaTypeAdapter;

import be.nabu.eai.module.keystore.persistance.KeyStorePersistanceArtifact;
import be.nabu.eai.repository.jaxb.ArtifactXMLAdapter;
import be.nabu.utils.security.resources.KeyStoreManagerConfiguration.KeyStoreConfiguration;

@XmlRootElement(name = "keystore")
public class KeyStoreArtifactConfiguration extends KeyStoreConfiguration {
	private KeyStorePersistanceArtifact persister;

	@XmlJavaTypeAdapter(value = ArtifactXMLAdapter.class)
	public KeyStorePersistanceArtifact getPersister() {
		return persister;
	}
	public void setPersister(KeyStorePersistanceArtifact persister) {
		this.persister = persister;
	}
}
