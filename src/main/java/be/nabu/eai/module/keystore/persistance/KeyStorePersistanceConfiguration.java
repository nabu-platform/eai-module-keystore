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

import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.adapters.XmlJavaTypeAdapter;

import be.nabu.eai.api.InterfaceFilter;
import be.nabu.eai.repository.jaxb.ArtifactXMLAdapter;
import be.nabu.libs.services.api.DefinedService;

@XmlRootElement(name = "keystorePersistance")
public class KeyStorePersistanceConfiguration {
	private DefinedService setService, getService, getAllService, deleteService;

	@InterfaceFilter(implement = "be.nabu.utils.security.basic.KeyStorePersistanceManager.set")
	@XmlJavaTypeAdapter(value = ArtifactXMLAdapter.class)
	public DefinedService getSetService() {
		return setService;
	}
	public void setSetService(DefinedService setService) {
		this.setService = setService;
	}

	@InterfaceFilter(implement = "be.nabu.utils.security.basic.KeyStorePersistanceManager.get")
	@XmlJavaTypeAdapter(value = ArtifactXMLAdapter.class)
	public DefinedService getGetService() {
		return getService;
	}
	public void setGetService(DefinedService getService) {
		this.getService = getService;
	}

	@InterfaceFilter(implement = "be.nabu.utils.security.basic.KeyStorePersistanceManager.getAll")
	@XmlJavaTypeAdapter(value = ArtifactXMLAdapter.class)
	public DefinedService getGetAllService() {
		return getAllService;
	}

	public void setGetAllService(DefinedService getAllService) {
		this.getAllService = getAllService;
	}

	@InterfaceFilter(implement = "be.nabu.utils.security.basic.KeyStorePersistanceManager.delete")
	@XmlJavaTypeAdapter(value = ArtifactXMLAdapter.class)
	public DefinedService getDeleteService() {
		return deleteService;
	}
	public void setDeleteService(DefinedService deleteService) {
		this.deleteService = deleteService;
	}
	
}
