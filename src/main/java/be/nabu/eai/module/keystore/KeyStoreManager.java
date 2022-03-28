package be.nabu.eai.module.keystore;

import java.io.IOException;
import java.security.KeyStoreException;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.List;

import be.nabu.eai.repository.api.ArtifactManager;
import be.nabu.eai.repository.api.ModifiableNodeEntry;
import be.nabu.eai.repository.api.ResourceEntry;
import be.nabu.libs.validator.api.Validation;
import be.nabu.libs.validator.api.ValidationMessage;
import be.nabu.libs.validator.api.ValidationMessage.Severity;

public class KeyStoreManager implements ArtifactManager<KeyStoreArtifact> {

	@Override
	public KeyStoreArtifact load(ResourceEntry entry, List<Validation<?>> messages) throws IOException, ParseException {
		return new KeyStoreArtifact(entry.getId(), entry.getContainer());
	}

	@Override
	public List<Validation<?>> save(ResourceEntry entry, KeyStoreArtifact artifact) throws IOException {
		try {
			artifact.save(entry.getContainer());
		}
		catch (KeyStoreException e) {
			List<Validation<?>> messages = new ArrayList<Validation<?>>();
			messages.add(new ValidationMessage(Severity.ERROR, "Could not save keystore: " + e.getMessage()));
			return messages;
		}
		if (entry instanceof ModifiableNodeEntry) {
			((ModifiableNodeEntry) entry).updateNode(getReferences(artifact));
		}
		return null;
	}

	@Override
	public Class<KeyStoreArtifact> getArtifactClass() {
		return KeyStoreArtifact.class;
	}

	@Override
	public List<String> getReferences(KeyStoreArtifact artifact) throws IOException {
		return null;
	}

	@Override
	public List<Validation<?>> updateReference(KeyStoreArtifact artifact, String from, String to) throws IOException {
		return null;
	}
	
}
