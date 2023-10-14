package be.nabu.eai.module.keystore;

import be.nabu.eai.repository.api.Repository;
import be.nabu.eai.repository.managers.base.JAXBArtifactManager;
import be.nabu.libs.resources.api.ResourceContainer;

public class KeyStoreManager extends JAXBArtifactManager<KeyStoreArtifactConfiguration, KeyStoreArtifact> {

	public KeyStoreManager() {
		super(KeyStoreArtifact.class);
	}

	@Override
	protected KeyStoreArtifact newInstance(String id, ResourceContainer<?> container, Repository repository) {
		return new KeyStoreArtifact(id, container, repository);
	}
	
}
