package be.nabu.eai.module.keystore.persistance;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import be.nabu.eai.developer.api.InterfaceLister;
import be.nabu.eai.developer.util.InterfaceDescriptionImpl;

public class KeyStorePersistanceInterfaceLister implements InterfaceLister {

	private static Collection<InterfaceDescription> descriptions = null;
	
	@Override
	public Collection<InterfaceDescription> getInterfaces() {
		if (descriptions == null) {
			synchronized(KeyStorePersistanceInterfaceLister.class) {
				if (descriptions == null) {
					List<InterfaceDescription> descriptions = new ArrayList<InterfaceDescription>();
					descriptions.add(new InterfaceDescriptionImpl("Keystore", "Keystore Persistance Get", "be.nabu.utils.security.basic.KeyStorePersistanceManager.get"));
					descriptions.add(new InterfaceDescriptionImpl("Keystore", "Keystore Persistance Set", "be.nabu.utils.security.basic.KeyStorePersistanceManager.set"));
					descriptions.add(new InterfaceDescriptionImpl("Keystore", "Keystore Persistance Get Aliases", "be.nabu.utils.security.basic.KeyStorePersistanceManager.getAliases"));
					descriptions.add(new InterfaceDescriptionImpl("Keystore", "Keystore Persistance Delete", "be.nabu.utils.security.basic.KeyStorePersistanceManager.delete"));
					KeyStorePersistanceInterfaceLister.descriptions = descriptions;
				}
			}
		}
		return descriptions;
	}

}
