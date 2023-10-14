package be.nabu.eai.module.keystore.persistance;

import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.adapters.XmlJavaTypeAdapter;

import be.nabu.eai.api.InterfaceFilter;
import be.nabu.eai.repository.jaxb.ArtifactXMLAdapter;
import be.nabu.libs.services.api.DefinedService;

@XmlRootElement(name = "keystorePersistance")
public class KeyStorePersistanceConfiguration {
	private DefinedService setService, getService, getAliasesService, deleteService;

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

	@InterfaceFilter(implement = "be.nabu.utils.security.basic.KeyStorePersistanceManager.getAliases")
	@XmlJavaTypeAdapter(value = ArtifactXMLAdapter.class)
	public DefinedService getGetAliasesService() {
		return getAliasesService;
	}

	public void setGetAliasesService(DefinedService getAliasesService) {
		this.getAliasesService = getAliasesService;
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
