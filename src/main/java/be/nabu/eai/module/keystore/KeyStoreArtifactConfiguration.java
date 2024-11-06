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
