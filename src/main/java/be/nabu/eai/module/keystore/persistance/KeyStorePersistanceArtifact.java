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
			getConfig().getGetAliasesService(),
			getConfig().getDeleteService()
		);
	}
}
