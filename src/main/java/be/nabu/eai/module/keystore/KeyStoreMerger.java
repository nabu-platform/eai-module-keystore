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

package be.nabu.eai.module.keystore;

import java.security.KeyStore;
import java.util.ArrayList;
import java.util.List;

import javafx.collections.FXCollections;
import javafx.scene.control.ListView;
import javafx.scene.control.ScrollPane;
import javafx.scene.layout.AnchorPane;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import be.nabu.eai.developer.api.ArtifactMerger;
import be.nabu.eai.repository.api.Repository;
import be.nabu.utils.security.api.KeyStoreEntryType;

public class KeyStoreMerger implements ArtifactMerger<KeyStoreArtifact> {

	private Logger logger = LoggerFactory.getLogger(getClass());
	
	@Override
	public boolean merge(KeyStoreArtifact source, KeyStoreArtifact target, AnchorPane pane, Repository targetRepository) {
		List<String> merged = new ArrayList<String>();
		if (source != null && target != null) {
			try {
				List<String> existing = new ArrayList<String>();
				for (String alias : source.getKeyStore().getAliases()) {
					existing.add(alias);
				}
				for (String alias : target.getKeyStore().getAliases()) {
					// if we don't have the alias in the source, we added it specifically in the target (e.g. acme), port it to the source
					// note that this makes it very hard to actually delete something
					// now we overwrite anything in the source with the target, we are using reverse proxies in all environments now (including dev) which means acme is active everywhere with different keys
					// worst case we can add some configuration to explicitly change this behavior
//					if (!existing.contains(alias)) {
						if (target.getKeyStore().getEntryType(alias) == KeyStoreEntryType.PRIVATE_KEY) {		// target.getKeyStore().getKeyStore().entryInstanceOf(alias, KeyStore.PrivateKeyEntry.class)
							source.getKeyStore().set(alias, target.getKeyStore().getPrivateKey(alias), target.getKeyStore().getChain(alias), target.getKeyStore().getPassword(alias));
						}
						else if (target.getKeyStore().getEntryType(alias) == KeyStoreEntryType.SECRET_KEY) {	// target.getKeyStore().getKeyStore().entryInstanceOf(alias, KeyStore.SecretKeyEntry.class)
							source.getKeyStore().set(alias, target.getKeyStore().getSecretKey(alias), target.getKeyStore().getPassword(alias));
						}
						else if (target.getKeyStore().getEntryType(alias) == KeyStoreEntryType.CERTIFICATE) {	// target.getKeyStore().getKeyStore().entryInstanceOf(alias, KeyStore.TrustedCertificateEntry.class)
							source.getKeyStore().set(alias, target.getKeyStore().getCertificate(alias));
						}
						merged.add(alias);
//					}
				}
			}
			catch (Exception e) {
				logger.error("Could not merge keystore: " + source.getId(), e);
			}
		}
		ListView<String> list = new ListView<String>();
		list.setItems(FXCollections.observableArrayList(merged));
		ScrollPane scroll = new ScrollPane();
		scroll.setContent(list);
		AnchorPane.setRightAnchor(scroll, 0d);
		AnchorPane.setTopAnchor(scroll, 0d);
		AnchorPane.setLeftAnchor(scroll, 0d);
		AnchorPane.setBottomAnchor(scroll, 0d);
		pane.getChildren().add(scroll);
		return true;
	}

	@Override
	public Class<KeyStoreArtifact> getArtifactClass() {
		return KeyStoreArtifact.class;
	}

}
