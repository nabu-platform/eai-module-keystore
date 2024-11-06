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

import java.io.BufferedOutputStream;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.OutputStream;
import java.io.StringReader;
import java.io.StringWriter;
import java.net.URI;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.Enumeration;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

import javafx.beans.value.ChangeListener;
import javafx.beans.value.ObservableValue;
import javafx.event.ActionEvent;
import javafx.event.EventHandler;
import javafx.scene.Node;
import javafx.scene.control.Button;
import javafx.scene.control.TableColumn;
import javafx.scene.control.TableView;
import javafx.scene.control.cell.PropertyValueFactory;
import javafx.scene.layout.AnchorPane;
import javafx.scene.layout.HBox;
import javafx.scene.layout.Priority;
import javafx.scene.layout.VBox;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.security.auth.x500.X500Principal;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import be.nabu.eai.developer.MainController;
import be.nabu.eai.developer.managers.base.BaseArtifactGUIInstance;
import be.nabu.eai.developer.managers.base.BasePortableGUIManager;
import be.nabu.eai.developer.managers.util.EnumeratedSimpleProperty;
import be.nabu.eai.developer.managers.util.SimpleProperty;
import be.nabu.eai.developer.managers.util.SimplePropertyUpdater;
import be.nabu.eai.developer.util.Confirm;
import be.nabu.eai.developer.util.Confirm.ConfirmType;
import be.nabu.eai.developer.util.EAIDeveloperUtils;
import be.nabu.eai.module.keystore.persistance.KeyStorePersistanceArtifact;
import be.nabu.eai.repository.EAIResourceRepository;
import be.nabu.eai.repository.api.Entry;
import be.nabu.eai.repository.api.ResourceEntry;
import be.nabu.eai.repository.resources.RepositoryEntry;
import be.nabu.libs.artifacts.api.Artifact;
import be.nabu.libs.property.api.Property;
import be.nabu.libs.property.api.Value;
import be.nabu.libs.types.base.ValueImpl;
import be.nabu.libs.validator.api.ValidationMessage;
import be.nabu.libs.validator.api.ValidationMessage.Severity;
import be.nabu.utils.security.BCSecurityUtils;
import be.nabu.utils.security.KeyPairType;
import be.nabu.utils.security.KeyStoreHandler;
import be.nabu.utils.security.SSLContextType;
import be.nabu.utils.security.SecurityUtils;
import be.nabu.utils.security.SignatureType;
import be.nabu.utils.security.StoreType;
import be.nabu.utils.security.api.KeyStoreEntryType;
import be.nabu.utils.security.api.ManagedKeyStore;
import be.nabu.utils.security.basic.BasicManagedKeyStore;
import be.nabu.utils.security.basic.NamedKeyStoreEntry;

public class KeyStoreGUIManager extends BasePortableGUIManager<KeyStoreArtifact, BaseArtifactGUIInstance<KeyStoreArtifact>> {

	private Logger logger = LoggerFactory.getLogger(getClass());
	private KeyStoreArtifact keystore;
	
	public KeyStoreGUIManager() {
		super("Java Keystore", KeyStoreArtifact.class, new KeyStoreManager());
	}

	@Override
	public String getCategory() {
		return "Security";
	}
	
	public enum UploadType {
		CERTIFICATE,
		JKS,
		PKCS12
	}
	
	public enum Duration {
		HOUR(1000l*60*60),
		DAY(1000l*60*60*24),
		MONTH(1000l*60*60*24*31),
		YEAR(1000l*60*60*24*365),
		TWO_YEARS(1000l*60*60*24*365*2),
		FIVE_YEARS(1000l*60*60*24*365*5),
		TEN_YEARS(1000l*60*60*24*365*10),
		FIFTEEN_YEARS(1000l*60*60*24*365*15),
		TWENTY_YEARS(1000l*60*60*24*365*20),
		TWENTY_FIVE_YEARS(1000l*60*60*24*365*25),
		THIRTY_YEARS(1000l*60*60*24*365*30),
		FORTY_YEARS(1000l*60*60*24*365*40),
		FIFTY_YEARS(1000l*60*60*24*365*50),
		SEVENTY_FIVE_YEARS(1000l*60*60*24*365*75),
		HUNDRED_YEARS(1000l*60*60*24*365*100)
		;
		
		private long ms;

		private Duration(long ms) {
			this.ms = ms;
		}

		public long getMs() {
			return ms;
		}
	}
	
	private <T extends Node> T ifType(T node, StoreType...type) {
		boolean visible = Arrays.asList(type).indexOf(keystore.getConfig().getType()) >= 0;
		node.setManaged(visible);
		node.setVisible(visible);
		return node;
	}
	private <T extends Node> T ifNotType(T node, StoreType...type) {
		boolean visible = keystore.getConfig().getType() == null || Arrays.asList(type).indexOf(keystore.getConfig().getType()) < 0;
		node.setManaged(visible);
		node.setVisible(visible);
		return node;
	}
	
	@Override
	public void display(MainController controller, AnchorPane pane, final KeyStoreArtifact keystore) {
		this.keystore = keystore;
		final TableView<KeyStoreEntry> table = createTable();
		try {
			table.getItems().addAll(toEntries(keystore.getKeyStore()));
		}
		catch (Exception e) {
			throw new RuntimeException(e);
		}
		
		VBox vbox = new VBox();
		HBox buttons = new HBox();
		
		Button newSecret = new Button("New Secret");
		newSecret.addEventHandler(ActionEvent.ANY, new EventHandler<ActionEvent>() {
			@SuppressWarnings({ "rawtypes", "unchecked" })
			@Override
			public void handle(ActionEvent arg0) {
				Set properties = new LinkedHashSet(Arrays.asList(new Property [] {
					new SimpleProperty<String>("Key Alias", String.class, true),
					new SimpleProperty<Integer>("Keysize", Integer.class, false),
				}));
				final SimplePropertyUpdater updater = new SimplePropertyUpdater(true, properties);
				
				EAIDeveloperUtils.buildPopup(MainController.getInstance(), updater, "Create Secret Key", new EventHandler<ActionEvent>() {
					@Override
					public void handle(ActionEvent arg0) {
						try {
							String keyAlias = updater.getValue("Key Alias");
							int keysize = updater.getValue("Keysize") == null ? 256 : updater.getValue("Keysize");
							KeyGenerator generator = KeyGenerator.getInstance("AES");
							generator.init(keysize);
							SecretKey key = generator.generateKey();
							keystore.getKeyStore().set(keyAlias == null ? "secretkey" : keyAlias, key, null);
							table.getItems().clear();
							table.getItems().addAll(toEntries(keystore.getKeyStore()));
							MainController.getInstance().setChanged();
						}
						catch (Exception e) {
							MainController.getInstance().notify(e);
						}
					}
				});
			}
		});
		ifNotType(newSecret, StoreType.JKS, StoreType.PKCS12);
		
		Button newSelfSigned = new Button("New Self Signed");
		newSelfSigned.addEventHandler(ActionEvent.ANY, new EventHandler<ActionEvent>() {
			@SuppressWarnings({ "rawtypes", "unchecked" })
			@Override
			public void handle(ActionEvent arg0) {
				Set properties = new LinkedHashSet(Arrays.asList(new Property [] {
					new SimpleProperty<String>("Key Alias", String.class, false),
					new SimpleProperty<String>("Certificate Alias", String.class, false),
					new SimpleProperty<Integer>("Keysize", Integer.class, false),
					new SimpleProperty<Duration>("Duration", Duration.class, false),
					new SimpleProperty<String>("Common Name", String.class, false),
					new SimpleProperty<String>("Organisation", String.class, false),
					new SimpleProperty<String>("Organisational Unit", String.class, false),
					new SimpleProperty<String>("Locality", String.class, false),
					new SimpleProperty<String>("State", String.class, false),
					new SimpleProperty<String>("Country", String.class, false)
				}));
				final SimplePropertyUpdater updater = new SimplePropertyUpdater(true, properties);
				
				EAIDeveloperUtils.buildPopup(MainController.getInstance(), updater, "Create Self Signed", new EventHandler<ActionEvent>() {
					@Override
					public void handle(ActionEvent arg0) {
						try {
							int keysize = updater.getValue("Keysize") == null ? 2048 : updater.getValue("Keysize");
							KeyPair keyPair = SecurityUtils.generateKeyPair(KeyPairType.RSA, keysize);
							X500Principal principal = SecurityUtils.createX500Principal(
								updater.getValue("Common Name"),
								updater.getValue("Organisation"),
								updater.getValue("Organisational Unit"),
								updater.getValue("Locality"),
								updater.getValue("State"),
								updater.getValue("Country")
							);
							Duration duration = updater.getValue("Duration");
							if (duration == null) {
								duration = Duration.YEAR;
							}
							String keyAlias = updater.getValue("Key Alias");
							String certificateAlias = updater.getValue("Certificate Alias");
							X509Certificate certificate = BCSecurityUtils.generateSelfSignedCertificate(keyPair, new Date(new Date().getTime() + duration.getMs()), principal, principal, SignatureType.SHA256WITHRSA);
							keystore.getKeyStore().set(certificateAlias == null ? "ca" : certificateAlias, certificate);
							keystore.getKeyStore().set(keyAlias == null ? "privkey" : keyAlias, keyPair.getPrivate(), new X509Certificate[] { certificate }, null);
							table.getItems().clear();
							table.getItems().addAll(toEntries(keystore.getKeyStore()));
							MainController.getInstance().setChanged();
						}
						catch (Exception e) {
							MainController.getInstance().notify(new ValidationMessage(Severity.ERROR, "Failed: " + e.getMessage()));
							logger.error("Could not generate self signed", e);
						}
					}
				});
			}
		});
//		ifNotType(newSelfSigned, StoreType.JWK);
	
		Button addCertificate = new Button("Add Certificate");
		addCertificate.addEventHandler(ActionEvent.ANY, new EventHandler<ActionEvent>() {
			@SuppressWarnings({ "unchecked", "rawtypes" })
			@Override
			public void handle(ActionEvent arg0) {
				Set properties = new LinkedHashSet(Arrays.asList(new Property [] {
					new SimpleProperty<String>("Alias", String.class, false),
					new SimpleProperty<byte[]>("Content", byte[].class, true)
				}));
				final SimplePropertyUpdater updater = new SimplePropertyUpdater(true, properties);
				EAIDeveloperUtils.buildPopup(MainController.getInstance(), updater, "Add To Keystore", new EventHandler<ActionEvent>() {
					@Override
					public void handle(ActionEvent arg0) {
						String alias = updater.getValue("Alias");
						byte [] content = updater.getValue("Content");
						if (alias == null) {
							alias = UUID.randomUUID().toString().replace("-", "");
						}
						try {
							if (content != null) {
								X509Certificate certificate = SecurityUtils.parseCertificate(new ByteArrayInputStream(content));
								keystore.getKeyStore().set(alias, certificate);
								MainController.getInstance().setChanged();
								table.getItems().clear();
								table.getItems().addAll(toEntries(keystore.getKeyStore()));
							}
						}
						catch (Exception e) {
							MainController.getInstance().notify(new ValidationMessage(Severity.ERROR, "Failed: " + e.getMessage()));
							logger.error("Could not add certificate", e);
						}
					}
				});
			}
		});
//		ifNotType(addCertificate, StoreType.JWK);
		
		final Button keyPassword = new Button("Key Password");
		keyPassword.setDisable(true);
		keyPassword.addEventHandler(ActionEvent.ANY, new EventHandler<ActionEvent>() {
			@SuppressWarnings({ "rawtypes", "unchecked" })
			@Override
			public void handle(ActionEvent arg0) {
				KeyStoreEntry selectedItem = table.getSelectionModel().getSelectedItem();
				if (selectedItem != null && selectedItem.getAlias() != null) {
					try {
						SimpleProperty<String> passwordProperty = new SimpleProperty<String>("Password", String.class, false);
						Set properties = new LinkedHashSet(Arrays.asList(new Property [] {
							passwordProperty,
						}));
						final String alias = selectedItem.getAlias();
						final String currentPassword = keystore.getKeyStore().getPassword(alias);
						final SimplePropertyUpdater updater = new SimplePropertyUpdater(true, properties, new ValueImpl<String>(passwordProperty, currentPassword));
						EAIDeveloperUtils.buildPopup(MainController.getInstance(), updater, "Key Password", new EventHandler<ActionEvent>() {
							@Override
							public void handle(ActionEvent arg0) {
								String password = updater.getValue("Password");
								if ((password == null && currentPassword != null) || (password != null && !password.equals(currentPassword))) {
									try {
										keystore.getKeyStore().set(
											alias, 
											keystore.getKeyStore().getPrivateKey(alias), 
											keystore.getKeyStore().getChain(alias), 
											password
										);
										MainController.getInstance().setChanged();
									}
									catch (Exception e) {
										throw new RuntimeException(e);		
									}
								}
							}
						});
					}
					catch (Exception e) {
						throw new RuntimeException(e);
					}
				}
			}
		});
//		ifNotType(keyPassword, StoreType.JWK);
		
		Button addKeystore = new Button("Add Keystore");
		addKeystore.addEventHandler(ActionEvent.ANY, new EventHandler<ActionEvent>() {
			@SuppressWarnings({ "unchecked", "rawtypes" })
			@Override
			public void handle(ActionEvent arg0) {
				Set properties = new LinkedHashSet(Arrays.asList(new Property [] {
					new SimpleProperty<byte[]>("Content", byte[].class, true),
					new SimpleProperty<String>("Password", String.class, false),
					new SimpleProperty<StoreType>("Store Type", StoreType.class, true)
				}));
				final SimplePropertyUpdater updater = new SimplePropertyUpdater(true, properties);
				EAIDeveloperUtils.buildPopup(MainController.getInstance(), updater, "Add To Keystore", new EventHandler<ActionEvent>() {
					@Override
					public void handle(ActionEvent arg0) {
						String password = updater.getValue("Password");
						StoreType type = updater.getValue("Store Type");
						byte [] content = updater.getValue("Content");
						try {
							if (content != null) {
								KeyStoreHandler toMerge = KeyStoreHandler.load(new ByteArrayInputStream(content), password, type == null ? StoreType.PKCS12 : type);
								Enumeration<String> aliases = toMerge.getKeyStore().aliases();
								while (aliases.hasMoreElements()) {
									String alias = aliases.nextElement();
									if (toMerge.getKeyStore().entryInstanceOf(alias, KeyStore.TrustedCertificateEntry.class)) {
										keystore.getKeyStore().set(alias, (X509Certificate) toMerge.getCertificate(alias));
									}
									else if (toMerge.getKeyStore().entryInstanceOf(alias, KeyStore.PrivateKeyEntry.class)) {
										keystore.getKeyStore().set(alias, (PrivateKey) toMerge.getPrivateKey(alias, null), (X509Certificate[]) toMerge.getPrivateKeys().get(alias), null);
									}
								}
								MainController.getInstance().setChanged();
								table.getItems().clear();
								table.getItems().addAll(toEntries(keystore.getKeyStore()));
							}
						}
						catch (Exception e) {
							MainController.getInstance().notify(new ValidationMessage(Severity.ERROR, "Failed: " + e.getMessage()));
							logger.error("Could not add keystore", e);
						}
					}
				});
			}
		});
//		ifNotType(addKeystore, StoreType.JWK);
		
		Button delete = new Button("Delete");
		delete.addEventHandler(ActionEvent.ANY, new EventHandler<ActionEvent>() {
			@Override
			public void handle(ActionEvent arg0) {
				KeyStoreEntry selectedItem = table.getSelectionModel().getSelectedItem();
				if (selectedItem != null) {
					try {
						keystore.getKeyStore().delete(selectedItem.getAlias());
						MainController.getInstance().setChanged();
						table.getItems().clear();
						table.getItems().addAll(toEntries(keystore.getKeyStore()));
					}
					catch (Exception e) {
						MainController.getInstance().notify(new ValidationMessage(Severity.ERROR, "Failed: " + e.getMessage()));
						logger.error("Could not delete: " + selectedItem.getAlias(), e);
					}
				}
			}
		});
		
		Button rename = new Button("Rename");
		rename.addEventHandler(ActionEvent.ANY, new EventHandler<ActionEvent>() {
			@SuppressWarnings({ "unchecked", "rawtypes" })
			@Override
			public void handle(ActionEvent arg0) {
				KeyStoreEntry selectedItem = table.getSelectionModel().getSelectedItem();
				if (selectedItem != null) {
					SimpleProperty<String> aliasProperty = new SimpleProperty<String>("Alias", String.class, false);
					Set properties = new LinkedHashSet(Arrays.asList(new Property [] { aliasProperty }));
					final SimplePropertyUpdater updater = new SimplePropertyUpdater(true, properties, new ValueImpl<String>(aliasProperty, selectedItem.getAlias()));
					EAIDeveloperUtils.buildPopup(MainController.getInstance(), updater, "Rename " + selectedItem.getAlias(), new EventHandler<ActionEvent>() {
						@Override
						public void handle(ActionEvent arg0) {
							String alias = updater.getValue("Alias");
							if (alias != null && !alias.isEmpty() && !selectedItem.getAlias().equals(alias)) {
								try {
									keystore.getKeyStore().rename(selectedItem.getAlias(), alias);
									MainController.getInstance().setChanged();
									table.getItems().clear();
									table.getItems().addAll(toEntries(keystore.getKeyStore()));
								}
								catch (Exception e) {
									MainController.getInstance().notify(new ValidationMessage(Severity.ERROR, "Failed: " + e.getMessage()));
									logger.error("Could not rename: " + selectedItem.getAlias(), e);
								}
							}
						}
					});
				}
			}
		});
//		ifNotType(rename, StoreType.JWK);
		
		Button download = new Button("Download");
		download.addEventHandler(ActionEvent.ANY, new EventHandler<ActionEvent>() {
			@SuppressWarnings({ "unchecked", "rawtypes" })
			@Override
			public void handle(ActionEvent arg0) {
				KeyStoreEntry selectedItem = table.getSelectionModel().getSelectedItem();
				if (selectedItem != null) {
					SimpleProperty<File> fileProperty = new SimpleProperty<File>("File", File.class, true);
					Set properties = new LinkedHashSet(Arrays.asList(new Property [] { fileProperty }));
					String extension = "Private Key".equals(selectedItem.getType()) ? "pkcs12" : "pem";
					SimpleProperty<String> password = new SimpleProperty<String>("Password", String.class, false);
					SimpleProperty<Boolean> includeKey = new SimpleProperty<Boolean>("Include Private Key", Boolean.class, false);
					if (extension.equals("pkcs12")) {
						properties.add(password);
						properties.add(includeKey);
					}
					final SimplePropertyUpdater updater = new SimplePropertyUpdater(true, properties, 
						new ValueImpl<Boolean>(includeKey, true),
						new ValueImpl<File>(fileProperty, new File(selectedItem.getAlias() + "." + extension)));
					EAIDeveloperUtils.buildPopup(MainController.getInstance(), updater, "Download " + selectedItem.getAlias(), new EventHandler<ActionEvent>() {
						@Override
						public void handle(ActionEvent arg0) {
							File file = updater.getValue("File");
							if (file != null) {
								try {
									if (keystore.getKeyStore().getEntryType(selectedItem.getAlias()) == KeyStoreEntryType.CERTIFICATE) {	// getKeyStore().entryInstanceOf(selectedItem.getAlias(), KeyStore.TrustedCertificateEntry.class)
										FileWriter writer = new FileWriter(file);
										try {
											SecurityUtils.encodeCertificate(keystore.getKeyStore().getCertificate(selectedItem.getAlias()), writer);
										}
										finally {
											writer.close();
										}
									}
									else if (keystore.getKeyStore().getEntryType(selectedItem.getAlias()) == KeyStoreEntryType.PRIVATE_KEY) {		// keystore.getKeyStore().getKeyStore().entryInstanceOf(selectedItem.getAlias(), KeyStore.PrivateKeyEntry.class)
										Boolean includeKey = updater.getValue("Include Private Key");
										String password = updater.getValue("Password");
										KeyStoreHandler temporary = KeyStoreHandler.create(password, StoreType.PKCS12);
										if (includeKey == null || includeKey) {
											temporary.set(selectedItem.getAlias(), keystore.getKeyStore().getPrivateKey(selectedItem.getAlias()), keystore.getKeyStore().getChain(selectedItem.getAlias()), null);
										}
										else {
											int counter = 0;
											X509Certificate[] chain = keystore.getKeyStore().getChain(selectedItem.getAlias());
											for (X509Certificate certificate : chain) {
												if (counter == 0) {
													temporary.set("self", certificate);
												}
												else if (counter == chain.length - 1) {
													temporary.set("root", certificate);
												}
												else {
													temporary.set("intermediate" + counter, certificate);
												}
												counter++;
											}
										}
										OutputStream output = new BufferedOutputStream(new FileOutputStream(file));
										try {
											temporary.save(output, password);
										}
										finally {
											output.close();
										}
									}
								}
								catch (Exception e) {
									MainController.getInstance().notify(new ValidationMessage(Severity.ERROR, "Failed: " + e.getMessage()));
									logger.error("Could not rename: " + selectedItem.getAlias(), e);
								}
							}
						}
					});
				}
			}
		});
		
		Button generatePKCS10 = new Button("Generate PKCS10");
		generatePKCS10.addEventHandler(ActionEvent.ANY, new EventHandler<ActionEvent>() {
			@SuppressWarnings({ "unchecked", "rawtypes" })
			@Override
			public void handle(ActionEvent arg0) {
				KeyStoreEntry selectedItem = table.getSelectionModel().getSelectedItem();
				if (selectedItem != null && "Private Key".equals(selectedItem.getType())) {
					SimpleProperty<File> fileProperty = new SimpleProperty<File>("File", File.class, true);
					SimpleProperty<SignatureType> signatureProperty = new SimpleProperty<SignatureType>("Signature Type", SignatureType.class, true);
					SimpleProperty<Boolean> encode = new SimpleProperty<Boolean>("Encode as base64", Boolean.class, true);
					Set properties = new LinkedHashSet(Arrays.asList(new Property [] { fileProperty, signatureProperty, encode }));
					
					final SimplePropertyUpdater updater = new SimplePropertyUpdater(true, properties, 
						new ValueImpl<File>(fileProperty, new File(selectedItem.getAlias() + ".pkcs10")),
						new ValueImpl<SignatureType>(signatureProperty, SignatureType.SHA256WITHRSA)
					);
					EAIDeveloperUtils.buildPopup(MainController.getInstance(), updater, "Generate PKCS10 for " + selectedItem.getAlias(), new EventHandler<ActionEvent>() {
						@Override
						public void handle(ActionEvent arg0) {
							File file = updater.getValue("File");
							SignatureType type = updater.getValue("Signature Type");
							if (type == null) {
								type = SignatureType.SHA256WITHRSA;
							}
							if (file != null) {
								try {
									Boolean encode = updater.getValue("Encode as base64");
									PrivateKey privateKey = (PrivateKey) keystore.getKeyStore().getPrivateKey(selectedItem.getAlias());
									PublicKey publicKey = keystore.getKeyStore().getChain(selectedItem.getAlias())[0].getPublicKey();
									KeyPair pair = new KeyPair(publicKey, privateKey);
									byte[] generatePKCS10 = BCSecurityUtils.generatePKCS10(pair, type, keystore.getKeyStore().getChain(selectedItem.getAlias())[0].getSubjectX500Principal());
									if (encode != null && encode) {
										StringWriter output = new StringWriter();
										BCSecurityUtils.encodePKCS10(new ByteArrayInputStream(generatePKCS10), output);
										generatePKCS10 = output.toString().getBytes("UTF-8");
									}
									OutputStream output = new BufferedOutputStream(new FileOutputStream(file));
									try {
										output.write(generatePKCS10);
									}
									finally {
										output.close();
									}
								}
								catch (Exception e) {
									MainController.getInstance().notify(new ValidationMessage(Severity.ERROR, "Failed: " + e.getMessage()));
									logger.error("Could not rename: " + selectedItem.getAlias(), e);
								}
							}
						}
					});
				}
			}
		});
//		ifNotType(generatePKCS10, StoreType.JWK);
		
		Button signPKCS10Entity = new Button("Sign PKCS10 (Entity)");
		signPKCS10Entity.addEventHandler(ActionEvent.ANY, new EventHandler<ActionEvent>() {
			@SuppressWarnings({ "unchecked", "rawtypes" })
			@Override
			public void handle(ActionEvent arg0) {
				KeyStoreEntry selectedItem = table.getSelectionModel().getSelectedItem();
				if (selectedItem != null && "Private Key".equals(selectedItem.getType())) {
					SimpleProperty<String> aliasProperty = new SimpleProperty<String>("Alias", String.class, false);
					SimpleProperty<byte[]> contentProperty = new SimpleProperty<byte[]>("PKCS10", byte[].class, true);
					SimpleProperty<Duration> durationProperty = new SimpleProperty<Duration>("Duration", Duration.class, false);
					SimpleProperty<SignatureType> signatureProperty = new SimpleProperty<SignatureType>("Signature Type", SignatureType.class, true);
					Set properties = new LinkedHashSet(Arrays.asList(new Property [] { aliasProperty, contentProperty, durationProperty, signatureProperty }));
					
					final SimplePropertyUpdater updater = new SimplePropertyUpdater(true, properties);
					EAIDeveloperUtils.buildPopup(MainController.getInstance(), updater, "Sign PKCS10 as entity using " + selectedItem.getAlias(), new EventHandler<ActionEvent>() {
						@Override
						public void handle(ActionEvent arg0) {
							String alias = updater.getValue("Alias");
							byte [] content = updater.getValue("PKCS10");
							Duration duration = updater.getValue("Duration");
							SignatureType type = updater.getValue("Signature Type");
							if (type == null) {
								type = SignatureType.SHA256WITHRSA;
							}
							if (duration == null) {
								duration = Duration.TWO_YEARS;
							}
							if (alias == null) {
								alias = UUID.randomUUID().toString().replace("-", "");
							}
							if (content != null) {
								try {
									PrivateKey privateKey = (PrivateKey) keystore.getKeyStore().getPrivateKey(selectedItem.getAlias());
									X500Principal principal = keystore.getKeyStore().getChain(selectedItem.getAlias())[0].getSubjectX500Principal();
									X509Certificate certificate = BCSecurityUtils.signPKCS10(content, new Date(new Date().getTime() + duration.getMs()), principal, privateKey, type);
									keystore.getKeyStore().set(alias, certificate);
									MainController.getInstance().setChanged();
									table.getItems().clear();
									table.getItems().addAll(toEntries(keystore.getKeyStore()));
								}
								catch (Exception e) {
									MainController.getInstance().notify(new ValidationMessage(Severity.ERROR, "Failed: " + e.getMessage()));
									logger.error("Could not rename: " + selectedItem.getAlias(), e);
								}
							}
						}
					});
				}
			}
		});
//		ifNotType(signPKCS10Entity, StoreType.JWK);
		
		Button signPKCS10Intermediate = new Button("Sign PKCS10 (Intermediate CA)");
		signPKCS10Intermediate.addEventHandler(ActionEvent.ANY, new EventHandler<ActionEvent>() {
			@SuppressWarnings({ "unchecked", "rawtypes" })
			@Override
			public void handle(ActionEvent arg0) {
				KeyStoreEntry selectedItem = table.getSelectionModel().getSelectedItem();
				if (selectedItem != null && "Private Key".equals(selectedItem.getType())) {
					SimpleProperty<String> aliasProperty = new SimpleProperty<String>("Alias", String.class, false);
					SimpleProperty<byte[]> contentProperty = new SimpleProperty<byte[]>("PKCS10", byte[].class, true);
					SimpleProperty<Duration> durationProperty = new SimpleProperty<Duration>("Duration", Duration.class, false);
					SimpleProperty<Integer> pathLengthProperty = new SimpleProperty<Integer>("Path Length", Integer.class, false);
					SimpleProperty<SignatureType> signatureProperty = new SimpleProperty<SignatureType>("Signature Type", SignatureType.class, true);
					Set properties = new LinkedHashSet(Arrays.asList(new Property [] { aliasProperty, contentProperty, durationProperty, signatureProperty, pathLengthProperty }));
					
					final SimplePropertyUpdater updater = new SimplePropertyUpdater(true, properties);
					EAIDeveloperUtils.buildPopup(MainController.getInstance(), updater, "Sign PKCS10 as intermediate using " + selectedItem.getAlias(), new EventHandler<ActionEvent>() {
						@Override
						public void handle(ActionEvent arg0) {
							String alias = updater.getValue("Alias");
							byte [] content = updater.getValue("PKCS10");
							Duration duration = updater.getValue("Duration");
							SignatureType type = updater.getValue("Signature Type");
							Integer pathLength = updater.getValue("Path Length");
							if (type == null) {
								type = SignatureType.SHA256WITHRSA;
							}
							if (duration == null) {
								duration = Duration.TWO_YEARS;
							}
							if (alias == null) {
								alias = UUID.randomUUID().toString().replace("-", "");
							}
							if (content != null) {
								try {
									PrivateKey privateKey = (PrivateKey) keystore.getKeyStore().getPrivateKey(selectedItem.getAlias());
									X500Principal principal = keystore.getKeyStore().getChain(selectedItem.getAlias())[0].getSubjectX500Principal();
									X509Certificate certificate = BCSecurityUtils.signPKCS10AsIntermediate(content, new Date(new Date().getTime() + duration.getMs()), principal, privateKey, type, keystore.getKeyStore().getChain(selectedItem.getAlias())[0], pathLength);
									keystore.getKeyStore().set(alias, certificate);
									MainController.getInstance().setChanged();
									table.getItems().clear();
									table.getItems().addAll(toEntries(keystore.getKeyStore()));
								}
								catch (Exception e) {
									MainController.getInstance().notify(new ValidationMessage(Severity.ERROR, "Failed: " + e.getMessage()));
									logger.error("Could not rename: " + selectedItem.getAlias(), e);
								}
							}
						}
					});
				}
			}
		});
//		ifNotType(signPKCS10Intermediate, StoreType.JWK);
		
		final Button showPassword = new Button("Show Password");
		showPassword.addEventHandler(ActionEvent.ANY, new EventHandler<ActionEvent>() {
			@SuppressWarnings({ "unchecked", "rawtypes" })
			@Override
			public void handle(ActionEvent arg0) {
				try {
					SimpleProperty<String> password = new SimpleProperty<String>("Password", String.class, false);
					Set properties = new LinkedHashSet(Arrays.asList(new Property [] { password }));
					final SimplePropertyUpdater updater = new SimplePropertyUpdater(false, properties, new ValueImpl<String>(password, keystore.getKeyStore().getPassword()));
					EAIDeveloperUtils.buildPopup(MainController.getInstance(), updater, "Password", null);
				}
				catch (Exception e) {
					logger.error("Could not show password", e);
				}
			}
		});
		
		final Button addRSAKey = new Button("Add RSA Private Key");
		addRSAKey.addEventHandler(ActionEvent.ANY, new EventHandler<ActionEvent>() {
			@SuppressWarnings({ "rawtypes", "unchecked" })
			@Override
			public void handle(ActionEvent arg0) {
				Set properties = new LinkedHashSet(Arrays.asList(new Property [] {
					new SimpleProperty<byte[]>("Private Key", byte[].class, true),
					new SimpleProperty<String>("Key Alias", String.class, false),
					new SimpleProperty<String>("Certificate Alias", String.class, false),
					new SimpleProperty<Duration>("Duration", Duration.class, false),
					new SimpleProperty<String>("Common Name", String.class, false),
					new SimpleProperty<String>("Organisation", String.class, false),
					new SimpleProperty<String>("Organisational Unit", String.class, false),
					new SimpleProperty<String>("Locality", String.class, false),
					new SimpleProperty<String>("State", String.class, false),
					new SimpleProperty<String>("Country", String.class, false)
				}));
				final SimplePropertyUpdater updater = new SimplePropertyUpdater(true, properties);
				
				EAIDeveloperUtils.buildPopup(MainController.getInstance(), updater, "Need to sign RSA key", new EventHandler<ActionEvent>() {
					@Override
					public void handle(ActionEvent arg0) {
						try {
							byte [] keyBytes = updater.getValue("Private Key");
							KeyPair keyPair = BCSecurityUtils.parseKeyPair(new StringReader(new String(keyBytes)));
							X500Principal principal = SecurityUtils.createX500Principal(
								updater.getValue("Common Name"),
								updater.getValue("Organisation"),
								updater.getValue("Organisational Unit"),
								updater.getValue("Locality"),
								updater.getValue("State"),
								updater.getValue("Country")
							);
							Duration duration = updater.getValue("Duration");
							if (duration == null) {
								duration = Duration.YEAR;
							}
							String keyAlias = updater.getValue("Key Alias");
							String certificateAlias = updater.getValue("Certificate Alias");
							X509Certificate certificate = BCSecurityUtils.generateSelfSignedCertificate(keyPair, new Date(new Date().getTime() + duration.getMs()), principal, principal, SignatureType.SHA256WITHRSA);
							keystore.getKeyStore().set(certificateAlias == null ? "ca" : certificateAlias, certificate);
							keystore.getKeyStore().set(keyAlias == null ? "privkey" : keyAlias, keyPair.getPrivate(), new X509Certificate[] { certificate }, null);
							table.getItems().clear();
							table.getItems().addAll(toEntries(keystore.getKeyStore()));
							MainController.getInstance().setChanged();
						}
						catch (Exception e) {
							MainController.getInstance().notify(new ValidationMessage(Severity.ERROR, "Failed: " + e.getMessage()));
							logger.error("Could not generate self signed", e);
						}
					}
				});
			}
		});
//		ifNotType(addRSAKey, StoreType.JWK);
		
		final Button addChain = new Button("Add Private Key");
		addChain.addEventHandler(ActionEvent.ANY, new EventHandler<ActionEvent>() {
			@SuppressWarnings({ "unchecked", "rawtypes" })
			@Override
			public void handle(ActionEvent arg0) {
				final KeyStoreEntry selectedItem = table.getSelectionModel().getSelectedItem();
				SimpleProperty<Integer> amountOfCertificatesProperty = new SimpleProperty<Integer>("Amount Of Certificates", Integer.class, true);
				final SimplePropertyUpdater chooseAmountUpdater = new SimplePropertyUpdater(true, new LinkedHashSet(Arrays.asList(new Property [] { amountOfCertificatesProperty })));
				EAIDeveloperUtils.buildPopup(MainController.getInstance(), chooseAmountUpdater, "Amount of certificates in chain", new EventHandler<ActionEvent>() {
					@Override
					public void handle(ActionEvent arg0) {
						int amountOfCertificates = chooseAmountUpdater.getValue("Amount Of Certificates");
						SimpleProperty<String> aliasProperty = new SimpleProperty<String>("Alias", String.class, false);
						SimpleProperty<String> passwordProperty = new SimpleProperty<String>("Password", String.class, false);
						Set properties = new LinkedHashSet(Arrays.asList(new Property [] { aliasProperty, passwordProperty }));
						boolean isPrivateKey = selectedItem != null && "Private Key".equals(selectedItem.getType());
						// if we did not select a private key, add it
						if (!isPrivateKey) {
							SimpleProperty<byte[]> keyProperty = new SimpleProperty<byte[]>("Private Key", byte[].class, true);
							properties.add(keyProperty);
						}
						for (int i = 0; i < amountOfCertificates; i++) {
							SimpleProperty<byte[]> certificateProperty = new SimpleProperty<byte[]>("Certificate[" + i + "]", byte[].class, true);
							certificateProperty.setDescription("The first certificate should be the certificate for your site, then the intermediaries and finally the root");
							properties.add(certificateProperty);
						}
						final SimplePropertyUpdater updater = new SimplePropertyUpdater(true, properties);
						EAIDeveloperUtils.buildPopup(MainController.getInstance(), updater, isPrivateKey ? "Add new chain to private key " + selectedItem.getAlias() : "Add a new private key", new EventHandler<ActionEvent>() {
							@Override
							public void handle(ActionEvent arg0) {
								String alias = updater.getValue("Alias");
								if (alias == null) {
									alias = selectedItem.getAlias();
								}
								String password = updater.getValue("Password");
								try {
									X509Certificate [] certificates = new X509Certificate[amountOfCertificates];
									for (int i = 0; i < amountOfCertificates; i++) {
										byte [] bytes = updater.getValue("Certificate[" + i + "]");
										certificates[i] = SecurityUtils.parseCertificate(new ByteArrayInputStream(bytes));
									}
									byte [] keyBytes = updater.getValue("Private Key");
									// try to check if it is encoded
									if (keyBytes != null && keyBytes[0] == '-' && keyBytes[1] == '-') {
										keyBytes = SecurityUtils.decode(new String(keyBytes, "ASCII"));
									}
									PrivateKey privateKey = keyBytes == null ? (PrivateKey) keystore.getKeyStore().getPrivateKey(selectedItem.getAlias()) : SecurityUtils.parsePKCS8Private(KeyPairType.RSA, keyBytes);
									keystore.getKeyStore().set(alias, privateKey, certificates, password);
									MainController.getInstance().setChanged();
									table.getItems().clear();
									table.getItems().addAll(toEntries(keystore.getKeyStore()));
								}
								catch (Exception e) {
									logger.error("Could not update certificate chain", e);
								}
							}
						});
					}
				});
			}
		});
//		ifNotType(addChain, StoreType.JWK);
		
		final Button addPKCS7 = new Button("Add PKCS7");
		addPKCS7.addEventHandler(ActionEvent.ANY, new EventHandler<ActionEvent>() {
			@SuppressWarnings({ "unchecked", "rawtypes" })
			@Override
			public void handle(ActionEvent arg0) {
				final KeyStoreEntry selectedItem = table.getSelectionModel().getSelectedItem();
				boolean isPrivateKey = selectedItem != null && "Private Key".equals(selectedItem.getType());
				
				SimpleProperty<byte[]> keyProperty = new SimpleProperty<byte[]>("PKCS7", byte[].class, true);
				Set properties = new LinkedHashSet(Arrays.asList(keyProperty));
				// can set a new alias for the new key
				if (isPrivateKey) {
					properties.add(new SimpleProperty<String>("Alias", String.class, false));
					properties.add(new SimpleProperty<String>("Password", String.class, false));
				}
				final SimplePropertyUpdater updater = new SimplePropertyUpdater(true, properties);
				EAIDeveloperUtils.buildPopup(MainController.getInstance(), updater, isPrivateKey ? "Add new chain to private key " + selectedItem.getAlias() : "Add new certificates", new EventHandler<ActionEvent>() {
					@Override
					public void handle(ActionEvent arg0) {
						try {
							byte [] keyBytes = updater.getValue("PKCS7");
							List<X509Certificate> certificates = BCSecurityUtils.parsePKCS7Certificates(keyBytes);
							if (certificates.isEmpty()) {
								throw new IllegalArgumentException("No certificates found");
							}
							if (isPrivateKey) {
								String alias = updater.getValue("Alias");
								if (alias == null) {
									alias = selectedItem.getAlias();
								}
								String password = updater.getValue("Password");
								PrivateKey key = (PrivateKey) keystore.getKeyStore().getPrivateKey(selectedItem.getAlias());
								List<X509Certificate> orderChain = SecurityUtils.orderChain(certificates);
								keystore.getKeyStore().set(alias, key, orderChain.toArray(new X509Certificate[0]), password);
							}
							else {
								int counter = 0;
								for (X509Certificate certificate : certificates) {
									keystore.getKeyStore().set("imported-certificate-" + counter++, certificate);
								}
							}
							MainController.getInstance().setChanged();
							table.getItems().clear();
							table.getItems().addAll(toEntries(keystore.getKeyStore()));
						}
						catch (Exception e) {
							MainController.getInstance().notify(e);
						}
					}
				});
			}
		});
//		ifNotType(addPKCS7, StoreType.JWK);
		
		final Button showChain = new Button("Show Chain");
		showChain.addEventHandler(ActionEvent.ANY, new EventHandler<ActionEvent>() {
			@Override
			public void handle(ActionEvent arg0) {
				final KeyStoreEntry selectedItem = table.getSelectionModel().getSelectedItem();
				boolean isPrivateKey = selectedItem != null && "Private Key".equals(selectedItem.getType());
				if (isPrivateKey) {
					try {
						StringBuilder builder = new StringBuilder();
						int counter = 0;
						for (X509Certificate certificate : keystore.getKeyStore().getChain(selectedItem.getAlias())) {
							builder.append("------------------------------- " + counter++ + " -------------------------------\n");
							builder.append("Subject: " + certificate.getSubjectX500Principal()).append("\n");
							builder.append("Issuer: " + certificate.getIssuerX500Principal()).append("\n");
						}
						Confirm.confirm(ConfirmType.INFORMATION, "Certificate chain for: " + selectedItem.getAlias(), builder.toString(), null);
					}
					catch (Exception e) {
						MainController.getInstance().notify(e);
					}
				}
			}
		});
		
		final Button addRemoteChain = new Button("Add Remote Chain");
		addRemoteChain.addEventHandler(ActionEvent.ANY, new EventHandler<ActionEvent>() {
			@SuppressWarnings({ "rawtypes", "unchecked" })
			@Override
			public void handle(ActionEvent arg0) {
				Set properties = new LinkedHashSet();
				properties.add(new SimpleProperty<String>("Host", String.class, true));
				properties.add(new SimpleProperty<Integer>("Port", Integer.class, false));
				final SimplePropertyUpdater updater = new SimplePropertyUpdater(true, properties);
				EAIDeveloperUtils.buildPopup(MainController.getInstance(), updater, "Add remote chain", new EventHandler<ActionEvent>() {
					@Override
					public void handle(ActionEvent arg0) {
						String host = updater.getValue("Host");
						if (host != null) {
							Integer port = updater.getValue("Port");
							if (port == null) {
								port = 443;
							}
							try {
								X509Certificate[] chain = SecurityUtils.getChain(host, port, SSLContextType.TLS);
								Set properties = new LinkedHashSet();
								for (int i = 0; i < chain.length; i++) {
									properties.add(new SimpleProperty<Boolean>("Add " + chain[i].getSubjectX500Principal(), Boolean.class, false));
								}
								SimplePropertyUpdater updater = new SimplePropertyUpdater(true, properties);
								EAIDeveloperUtils.buildPopup(MainController.getInstance(), updater, "Add remote chain", new EventHandler<ActionEvent>() {
									@Override
									public void handle(ActionEvent arg0) {
										for (int i = 0; i < chain.length; i++) {
											Boolean value = updater.getValue("Add " + chain[i].getSubjectX500Principal());
											if (value != null && value) {
												try {
													keystore.getKeyStore().set("imported-certificate-" + chain[i].getSerialNumber(), chain[i]);
												}
												catch (Exception e) {
													MainController.getInstance().notify(e);
												}
											}
										}
										MainController.getInstance().setChanged();
										table.getItems().clear();
										try {
											table.getItems().addAll(toEntries(keystore.getKeyStore()));
										}
										catch (Exception e) {
											MainController.getInstance().notify(e);
										}
									}
								});
							}
							catch (Exception e) {
								MainController.getInstance().notify(e);
							}
						}
					}
				});
				
			}
		});
//		ifNotType(addRemoteChain, StoreType.JWK);
		
		final Button downloadSSHPublic = new Button("As SSH Public");
		downloadSSHPublic.addEventHandler(ActionEvent.ANY, new EventHandler<ActionEvent>() {
			@SuppressWarnings({ "unchecked", "rawtypes" })
			@Override
			public void handle(ActionEvent arg0) {
				final KeyStoreEntry selectedItem = table.getSelectionModel().getSelectedItem();
				boolean isPrivateKey = selectedItem != null && "Private Key".equals(selectedItem.getType());
				if (isPrivateKey) {
					SimpleProperty<File> fileProperty = new SimpleProperty<File>("File", File.class, true);
					Set properties = new LinkedHashSet(Arrays.asList(new Property [] { fileProperty }));
					final SimplePropertyUpdater updater = new SimplePropertyUpdater(true, properties, 
						new ValueImpl<File>(fileProperty, new File("id_rsa_" + selectedItem.getAlias() + ".pub")));
					EAIDeveloperUtils.buildPopup(MainController.getInstance(), updater, "Download " + selectedItem.getAlias(), new EventHandler<ActionEvent>() {
						@Override
						public void handle(ActionEvent arg0) {
							File file = updater.getValue("File");
							if (file != null) {
								StringWriter writer = new StringWriter();
								try {
									BCSecurityUtils.writeSSHKey(writer, keystore.getKeyStore().getChain(selectedItem.getAlias())[0].getPublicKey());
									OutputStream output = new BufferedOutputStream(new FileOutputStream(file));
									try {
										output.write(writer.toString().getBytes("UTF-8"));
									}
									finally {
										output.close();
									}
								}
								catch (Exception e) {
									MainController.getInstance().notify(e);
								}
							}
						}
					});
				}
			}
		});
		
		final Button downloadSSHPrivate = new Button("As SSH Private");
		downloadSSHPrivate.addEventHandler(ActionEvent.ANY, new EventHandler<ActionEvent>() {
			@SuppressWarnings({ "unchecked", "rawtypes" })
			@Override
			public void handle(ActionEvent arg0) {
				final KeyStoreEntry selectedItem = table.getSelectionModel().getSelectedItem();
				boolean isPrivateKey = selectedItem != null && "Private Key".equals(selectedItem.getType());
				if (isPrivateKey) {
					SimpleProperty<File> fileProperty = new SimpleProperty<File>("File", File.class, true);
					Set properties = new LinkedHashSet(Arrays.asList(new Property [] { fileProperty , new SimpleProperty<String>("Password", String.class, false) }));
					final SimplePropertyUpdater updater = new SimplePropertyUpdater(true, properties, 
						new ValueImpl<File>(fileProperty, new File("id_rsa_" + selectedItem.getAlias())));
					EAIDeveloperUtils.buildPopup(MainController.getInstance(), updater, "Download " + selectedItem.getAlias(), new EventHandler<ActionEvent>() {
						@Override
						public void handle(ActionEvent arg0) {
							File file = updater.getValue("File");
							String password = updater.getValue("Password");
							if (password != null && password.trim().isEmpty()) {
								password = null;
							}
							if (file != null) {
								StringWriter writer = new StringWriter();
								try {
									BCSecurityUtils.writeSSHKey(writer, keystore.getKeyStore().getPrivateKey(selectedItem.getAlias()), password);
									OutputStream output = new BufferedOutputStream(new FileOutputStream(file));
									try {
										output.write(writer.toString().getBytes("UTF-8"));
									}
									finally {
										output.close();
									}
								}
								catch (Exception e) {
									MainController.getInstance().notify(e);
								}
							}
						}
					});
				}
			}
		});
		
		final Button setJWKUrl = new Button("Set JWK URL");
		setJWKUrl.addEventHandler(ActionEvent.ANY, new EventHandler<ActionEvent>() {
			@SuppressWarnings({ "rawtypes", "unchecked" })
			@Override
			public void handle(ActionEvent arg0) {
				Set properties = new LinkedHashSet();
				properties.add(new SimpleProperty<URI>("URL", URI.class, true));
				final SimplePropertyUpdater updater = new SimplePropertyUpdater(true, properties);
				EAIDeveloperUtils.buildPopup(MainController.getInstance(), updater, "Set JWK URL", new EventHandler<ActionEvent>() {
					@Override
					public void handle(ActionEvent arg0) {
						URI uri = updater.getValue("URL");
						if (uri != null) {
							
						}
					}
				});
			}
		});
//		ifType(setJWKUrl, StoreType.JWK);

		table.getSelectionModel().selectedItemProperty().addListener(new ChangeListener<KeyStoreEntry>() {
			@Override
			public void changed(ObservableValue<? extends KeyStoreEntry> arg0, KeyStoreEntry arg1, KeyStoreEntry selectedItem) {
				if (selectedItem != null && "Private Key".equals(selectedItem.getType())) {
					addChain.setText("Add Key Chain");
					addPKCS7.setText("Add PKCS7 chain");
					keyPassword.setDisable(false);
					signPKCS10Entity.setDisable(false);
					signPKCS10Intermediate.setDisable(false);
					showChain.setDisable(false);
					downloadSSHPublic.setDisable(false);
					downloadSSHPrivate.setDisable(false);
				}
				else {
					addChain.setText("Add Private Key");
					addPKCS7.setText("Add PKCS7");
					keyPassword.setDisable(true);
					signPKCS10Entity.setDisable(true);
					signPKCS10Intermediate.setDisable(true);
					showChain.setDisable(true);
					downloadSSHPublic.setDisable(true);
					downloadSSHPrivate.setDisable(true);
				}
			}
		});
		
		buttons.getChildren().addAll(newSelfSigned, newSecret, download, rename, delete, generatePKCS10, signPKCS10Entity, signPKCS10Intermediate, showPassword);
		HBox buttons2 = new HBox();
		buttons2.getChildren().addAll(addCertificate, addKeystore, addChain, keyPassword, addPKCS7, showChain, addRemoteChain, downloadSSHPublic, downloadSSHPrivate, addRSAKey);
		vbox.getChildren().addAll(buttons, buttons2, table);
		AnchorPane.setLeftAnchor(vbox, 0d);
		AnchorPane.setRightAnchor(vbox, 0d);
		AnchorPane.setTopAnchor(vbox, 0d);
		AnchorPane.setBottomAnchor(vbox, 0d);
		VBox.setVgrow(buttons, Priority.NEVER);
		VBox.setVgrow(table, Priority.ALWAYS);
		pane.getChildren().add(vbox);
	}
	
	private List<KeyStoreEntry> toEntries(ManagedKeyStore keystore) throws KeyStoreException, IOException {
		List<KeyStoreEntry> entries = new ArrayList<KeyStoreEntry>();
		// when using basic keystores, we don't want to do separate gets but rather a full get
		KeyStoreHandler keyStoreHandler = new KeyStoreHandler(keystore.getUnsecuredKeyStore());
		Map<String, X509Certificate[]> privateKeys = keyStoreHandler.getPrivateKeys();
		for (String alias : privateKeys.keySet()) {
			KeyStoreEntry entry = new KeyStoreEntry();
			entry.setAlias(alias);
			X509Certificate certificate = privateKeys.get(alias)[0];
			entry.setIssuer(certificate.getIssuerX500Principal().toString());
			entry.setSubject(certificate.getSubjectX500Principal().toString());
			entry.setNotAfter(certificate.getNotAfter());
			entry.setNotBefore(certificate.getNotBefore());
			entry.setChainLength(privateKeys.get(alias).length);
			entry.setType("Private Key");
			entries.add(entry);
		}
		Map<String, X509Certificate> certificates = keyStoreHandler.getCertificates();
		for (String alias : certificates.keySet()) {
			KeyStoreEntry entry = new KeyStoreEntry();
			entry.setAlias(alias);
			X509Certificate certificate = certificates.get(alias);
			entry.setIssuer(certificate.getIssuerX500Principal().toString());
			entry.setSubject(certificate.getSubjectX500Principal().toString());
			entry.setNotAfter(certificate.getNotAfter());
			entry.setNotBefore(certificate.getNotBefore());
			entry.setType("Certificate");
			entries.add(entry);
		}
		for (String alias : keyStoreHandler.getSecretKeys()) {
			KeyStoreEntry entry = new KeyStoreEntry();
			entry.setAlias(alias);
			entry.setType("Secret Key");
			entries.add(entry);
		}
//		for (String alias : keystore.getAliases()) {
//			KeyStoreEntry entry = new KeyStoreEntry();
//			entry.setAlias(alias);
//
//			X509Certificate certificate = null;
//			// a certificate
//			if (keystore.getEntryType(alias) == KeyStoreEntryType.CERTIFICATE) {		// keystore.getKeyStore().entryInstanceOf(alias, KeyStore.TrustedCertificateEntry.class)
//				certificate = keystore.getCertificate(alias);
//				entry.setType("Certificate");
//			}
//			else if (keystore.getEntryType(alias) == KeyStoreEntryType.PRIVATE_KEY) {		// keystore.getKeyStore().entryInstanceOf(alias, KeyStore.PrivateKeyEntry.class)
//				X509Certificate[] chain = keystore.getChain(alias);
//				certificate = chain[0];
//				entry.setChainLength(chain.length);
//				entry.setType("Private Key");
//			}
//			else if (keystore.getEntryType(alias) == KeyStoreEntryType.SECRET_KEY) {		// keystore.getKeyStore().entryInstanceOf(alias, KeyStore.SecretKeyEntry.class)
//				entry.setType("Secret Key");
//			}
//			else {
//				entry.setType("Unknown");
//			}
//			if (certificate != null) {
//				entry.setIssuer(certificate.getIssuerX500Principal().toString());
//				entry.setSubject(certificate.getSubjectX500Principal().toString());
//				entry.setNotAfter(certificate.getNotAfter());
//				entry.setNotBefore(certificate.getNotBefore());
//			}
//			entries.add(entry);
//		}
		return entries;
	}

	@Override
	protected List<Property<?>> getCreateProperties() {
		EnumeratedSimpleProperty<String> enumeratedSimpleProperty = new EnumeratedSimpleProperty<String>("Type", String.class, false);
		for (StoreType type : StoreType.values()) {
			enumeratedSimpleProperty.addAll(type.name());
		}
		// TODO: add all persistance providers (the id of the artifact)
		for (KeyStorePersistanceArtifact persister : EAIResourceRepository.getInstance().getArtifacts(KeyStorePersistanceArtifact.class)) {
			enumeratedSimpleProperty.addAll(persister.getId());
		}
		// TODO: retrofit create to take this into account
		return Arrays.asList(
//			new SimpleProperty<String>("Password", String.class, true), 
			//new SimpleProperty<StoreType>("Type", StoreType.class, false));
			enumeratedSimpleProperty);
	}

	@Override
	protected BaseArtifactGUIInstance<KeyStoreArtifact> newGUIInstance(Entry entry) {
		return new BaseArtifactGUIInstance<KeyStoreArtifact>(this, (ResourceEntry) entry);
	}

	@Override
	protected KeyStoreArtifact newInstance(MainController controller, RepositoryEntry entry, Value<?>...values) throws IOException {
		KeyStoreArtifact keystore = new KeyStoreArtifact(entry.getId(), entry.getContainer(), entry.getRepository());
//		keystore.create(getValue("Password", String.class, values), getValue("Type", StoreType.class, values));
		String value = getValue("Type", String.class, values);
		if (value == null) {
			value = "JKS";
		}
		if (value.equals("JKS") || value.equals("JCEKS") || value.equals("PKCS12")) {
			keystore.create(null, StoreType.valueOf(value));
		}
		else {
			KeyStorePersistanceArtifact resolved = (KeyStorePersistanceArtifact) entry.getRepository().resolve(value);
			if (resolved == null) {
				throw new IllegalArgumentException("Can not resolve persistence manager: " + value);
			}
			keystore.create(null, resolved);
		}
		return keystore;
	}

	@Override
	protected void setInstance(BaseArtifactGUIInstance<KeyStoreArtifact> guiInstance, KeyStoreArtifact instance) {
		guiInstance.setArtifact(instance);
	}

	@Override
	protected void setEntry(BaseArtifactGUIInstance<KeyStoreArtifact> guiInstance, ResourceEntry entry) {
		guiInstance.setEntry(entry);
	}
	
	private TableView<KeyStoreEntry> createTable() {
		TableView<KeyStoreEntry> table = new TableView<KeyStoreEntry>();
		table.getColumns().add(newColumn("Alias", 125));
		table.getColumns().add(newColumn("Type", 75));
		table.getColumns().add(newColumn("Subject", 250));
		table.getColumns().add(newColumn("Issuer", 250));
		table.getColumns().add(newColumn("Chain Length", 20));
		table.getColumns().add(newColumn("Not After", 200));
		table.getColumns().add(newColumn("Not Before", 200));
		return table;
	}
	
	private TableColumn<KeyStoreEntry, String> newColumn(String name, int width) {
		TableColumn<KeyStoreEntry, String> column = new TableColumn<KeyStoreEntry, String>();
		column.setText(name);
		column.setCellValueFactory(
			new PropertyValueFactory<KeyStoreEntry, String>(name.substring(0, 1).toLowerCase() + name.substring(1).replace(" ", ""))
		);
		column.setPrefWidth(width);
		return column;
	}
	
	public static class KeyStoreEntry {
		private String alias, subject, issuer, type;
		private Date notAfter, notBefore;
		private int chainLength;
		public String getAlias() {
			return alias;
		}
		public void setAlias(String alias) {
			this.alias = alias;
		}
		public String getSubject() {
			return subject;
		}
		public void setSubject(String subject) {
			this.subject = subject;
		}
		public String getIssuer() {
			return issuer;
		}
		public void setIssuer(String issuer) {
			this.issuer = issuer;
		}
		public Date getNotAfter() {
			return notAfter;
		}
		public void setNotAfter(Date notAfter) {
			this.notAfter = notAfter;
		}
		public Date getNotBefore() {
			return notBefore;
		}
		public void setNotBefore(Date notBefore) {
			this.notBefore = notBefore;
		}
		public int getChainLength() {
			return chainLength;
		}
		public void setChainLength(int chainLength) {
			this.chainLength = chainLength;
		}
		public String getType() {
			return type;
		}
		public void setType(String type) {
			this.type = type;
		}
		
	}
}
