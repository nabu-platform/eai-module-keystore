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

package be.nabu.eai.module.keystore.persistance;

import be.nabu.eai.repository.api.Repository;
import be.nabu.eai.repository.artifacts.jaxb.JAXBArtifact;
import be.nabu.eai.repository.util.SystemPrincipal;
import be.nabu.libs.resources.api.ResourceContainer;
import be.nabu.libs.services.pojo.POJOUtils;
import be.nabu.utils.security.basic.KeyStorePersistanceManager;

/**
 * Retains all the services necessary to support keystore persistance
 */
public class KeyStorePersistanceArtifact extends JAXBArtifact<KeyStorePersistanceConfiguration> {

	public KeyStorePersistanceArtifact(String id, ResourceContainer<?> directory, Repository repository) {
		super(id, directory, repository, "keystore-persistance.xml", KeyStorePersistanceConfiguration.class);
	}
	
	public KeyStorePersistanceManager getManager() {
		return POJOUtils.newProxy(KeyStorePersistanceManager.class, getRepository(), SystemPrincipal.ROOT, getRepository().getServiceRunner(), 
			getConfig().getGetService(),
			getConfig().getSetService(),
			getConfig().getGetAllService(),
			getConfig().getDeleteService()
		);
	}
}
