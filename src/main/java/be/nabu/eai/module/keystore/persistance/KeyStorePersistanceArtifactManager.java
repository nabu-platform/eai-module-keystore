package be.nabu.eai.module.keystore.persistance;

import be.nabu.eai.repository.api.Repository;
import be.nabu.eai.repository.managers.base.JAXBArtifactManager;
import be.nabu.libs.resources.api.ResourceContainer;

public class KeyStorePersistanceArtifactManager extends JAXBArtifactManager<KeyStorePersistanceConfiguration, KeyStorePersistanceArtifact> {

	public KeyStorePersistanceArtifactManager() {
		super(KeyStorePersistanceArtifact.class);
	}

	@Override
	protected KeyStorePersistanceArtifact newInstance(String id, ResourceContainer<?> container, Repository repository) {
		return new KeyStorePersistanceArtifact(id, container, repository);
	}

}
