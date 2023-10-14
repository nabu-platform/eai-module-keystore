package be.nabu.eai.module.keystore.persistance;

import java.io.IOException;
import java.util.List;

import be.nabu.eai.developer.MainController;
import be.nabu.eai.developer.managers.base.BaseJAXBGUIManager;
import be.nabu.eai.repository.resources.RepositoryEntry;
import be.nabu.libs.property.api.Property;
import be.nabu.libs.property.api.Value;

public class KeyStorePersistanceArtifactGUIManager extends BaseJAXBGUIManager<KeyStorePersistanceConfiguration, KeyStorePersistanceArtifact> {

	public KeyStorePersistanceArtifactGUIManager() {
		super("Keystore Persistance Manager", KeyStorePersistanceArtifact.class, new KeyStorePersistanceArtifactManager(), KeyStorePersistanceConfiguration.class);
	}

	@Override
	protected List<Property<?>> getCreateProperties() {
		return null;
	}

	@Override
	protected KeyStorePersistanceArtifact newInstance(MainController controller, RepositoryEntry entry, Value<?>...values) throws IOException {
		return new KeyStorePersistanceArtifact(entry.getId(), entry.getContainer(), entry.getRepository());
	}

	@Override
	public String getCategory() {
		return "Security";
	}
}
