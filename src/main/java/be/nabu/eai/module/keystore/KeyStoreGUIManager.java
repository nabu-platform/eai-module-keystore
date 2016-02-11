package be.nabu.eai.module.keystore;

import java.io.BufferedOutputStream;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.OutputStream;
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
import java.util.Set;
import java.util.UUID;

import javafx.event.EventHandler;
import javafx.scene.control.Button;
import javafx.scene.control.TableColumn;
import javafx.scene.control.TableView;
import javafx.scene.control.cell.PropertyValueFactory;
import javafx.scene.input.MouseEvent;
import javafx.scene.layout.AnchorPane;
import javafx.scene.layout.HBox;
import javafx.scene.layout.Priority;
import javafx.scene.layout.VBox;

import javax.security.auth.x500.X500Principal;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import be.nabu.eai.developer.MainController;
import be.nabu.eai.developer.managers.base.BaseArtifactGUIInstance;
import be.nabu.eai.developer.managers.base.BasePortableGUIManager;
import be.nabu.eai.developer.managers.util.SimpleProperty;
import be.nabu.eai.developer.managers.util.SimplePropertyUpdater;
import be.nabu.eai.developer.util.EAIDeveloperUtils;
import be.nabu.eai.repository.api.Entry;
import be.nabu.eai.repository.api.ResourceEntry;
import be.nabu.eai.repository.resources.RepositoryEntry;
import be.nabu.libs.property.api.Property;
import be.nabu.libs.property.api.Value;
import be.nabu.libs.types.base.ValueImpl;
import be.nabu.libs.validator.api.ValidationMessage;
import be.nabu.libs.validator.api.ValidationMessage.Severity;
import be.nabu.utils.security.BCSecurityUtils;
import be.nabu.utils.security.KeyPairType;
import be.nabu.utils.security.KeyStoreHandler;
import be.nabu.utils.security.SecurityUtils;
import be.nabu.utils.security.SignatureType;
import be.nabu.utils.security.StoreType;
import be.nabu.utils.security.api.ManagedKeyStore;

public class KeyStoreGUIManager extends BasePortableGUIManager<KeyStoreArtifact, BaseArtifactGUIInstance<KeyStoreArtifact>> {

	private Logger logger = LoggerFactory.getLogger(getClass());
	
	public KeyStoreGUIManager() {
		super("Key Store", KeyStoreArtifact.class, new KeyStoreManager());
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
		TEN_YEARS(1000l*60*60*24*365*10);
		
		private long ms;

		private Duration(long ms) {
			this.ms = ms;
		}

		public long getMs() {
			return ms;
		}
	}
	
	@Override
	public void display(MainController controller, AnchorPane pane, final KeyStoreArtifact keystore) {
		final TableView<KeyStoreEntry> table = createTable();
		try {
			table.getItems().addAll(toEntries(keystore.getKeyStore()));
		}
		catch (Exception e) {
			throw new RuntimeException(e);
		}
		
		VBox vbox = new VBox();
		HBox buttons = new HBox();
		Button newSelfSigned = new Button("New Self Signed");
		newSelfSigned.addEventHandler(MouseEvent.MOUSE_CLICKED, new EventHandler<MouseEvent>() {
			@SuppressWarnings({ "rawtypes", "unchecked" })
			@Override
			public void handle(MouseEvent arg0) {
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
				
				EAIDeveloperUtils.buildPopup(MainController.getInstance(), updater, "Create Self Signed", new EventHandler<MouseEvent>() {
					@Override
					public void handle(MouseEvent arg0) {
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
	
		Button addCertificate = new Button("Add Certificate");
		addCertificate.addEventHandler(MouseEvent.MOUSE_CLICKED, new EventHandler<MouseEvent>() {
			@SuppressWarnings({ "unchecked", "rawtypes" })
			@Override
			public void handle(MouseEvent arg0) {
				Set properties = new LinkedHashSet(Arrays.asList(new Property [] {
					new SimpleProperty<String>("Alias", String.class, false),
					new SimpleProperty<byte[]>("Content", byte[].class, true)
				}));
				final SimplePropertyUpdater updater = new SimplePropertyUpdater(true, properties);
				EAIDeveloperUtils.buildPopup(MainController.getInstance(), updater, "Add To Keystore", new EventHandler<MouseEvent>() {
					@Override
					public void handle(MouseEvent arg0) {
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
		
		Button addKeystore = new Button("Add Keystore");
		addKeystore.addEventHandler(MouseEvent.MOUSE_CLICKED, new EventHandler<MouseEvent>() {
			@SuppressWarnings({ "unchecked", "rawtypes" })
			@Override
			public void handle(MouseEvent arg0) {
				Set properties = new LinkedHashSet(Arrays.asList(new Property [] {
					new SimpleProperty<byte[]>("Content", byte[].class, true),
					new SimpleProperty<String>("Password", String.class, false),
					new SimpleProperty<StoreType>("Store Type", StoreType.class, true)
				}));
				final SimplePropertyUpdater updater = new SimplePropertyUpdater(true, properties);
				EAIDeveloperUtils.buildPopup(MainController.getInstance(), updater, "Add To Keystore", new EventHandler<MouseEvent>() {
					@Override
					public void handle(MouseEvent arg0) {
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
		
		Button delete = new Button("Delete");
		delete.addEventHandler(MouseEvent.MOUSE_CLICKED, new EventHandler<MouseEvent>() {
			@Override
			public void handle(MouseEvent arg0) {
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
		rename.addEventHandler(MouseEvent.MOUSE_CLICKED, new EventHandler<MouseEvent>() {
			@SuppressWarnings({ "unchecked", "rawtypes" })
			@Override
			public void handle(MouseEvent arg0) {
				KeyStoreEntry selectedItem = table.getSelectionModel().getSelectedItem();
				if (selectedItem != null) {
					SimpleProperty<String> aliasProperty = new SimpleProperty<String>("Alias", String.class, false);
					Set properties = new LinkedHashSet(Arrays.asList(new Property [] { aliasProperty }));
					final SimplePropertyUpdater updater = new SimplePropertyUpdater(true, properties, new ValueImpl<String>(aliasProperty, selectedItem.getAlias()));
					EAIDeveloperUtils.buildPopup(MainController.getInstance(), updater, "Rename " + selectedItem.getAlias(), new EventHandler<MouseEvent>() {
						@Override
						public void handle(MouseEvent arg0) {
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
		
		Button download = new Button("Download");
		download.addEventHandler(MouseEvent.MOUSE_CLICKED, new EventHandler<MouseEvent>() {
			@SuppressWarnings({ "unchecked", "rawtypes" })
			@Override
			public void handle(MouseEvent arg0) {
				KeyStoreEntry selectedItem = table.getSelectionModel().getSelectedItem();
				if (selectedItem != null) {
					SimpleProperty<File> fileProperty = new SimpleProperty<File>("File", File.class, true);
					Set properties = new LinkedHashSet(Arrays.asList(new Property [] { fileProperty }));
					String extension = "Private Key".equals(selectedItem.getType()) ? "pkcs12" : "pem";
					final SimplePropertyUpdater updater = new SimplePropertyUpdater(true, properties, new ValueImpl<File>(fileProperty, new File(selectedItem.getAlias() + "." + extension)));
					EAIDeveloperUtils.buildPopup(MainController.getInstance(), updater, "Download " + selectedItem.getAlias(), new EventHandler<MouseEvent>() {
						@Override
						public void handle(MouseEvent arg0) {
							File file = updater.getValue("File");
							if (file != null) {
								try {
									if (keystore.getKeyStore().getKeyStore().entryInstanceOf(selectedItem.getAlias(), KeyStore.TrustedCertificateEntry.class)) {
										FileWriter writer = new FileWriter(file);
										try {
											SecurityUtils.encodeCertificate(keystore.getKeyStore().getCertificate(selectedItem.getAlias()), writer);
										}
										finally {
											writer.close();
										}
									}
									else if (keystore.getKeyStore().getKeyStore().entryInstanceOf(selectedItem.getAlias(), KeyStore.PrivateKeyEntry.class)) {
										KeyStoreHandler temporary = KeyStoreHandler.create(keystore.getKeyStore().getPassword(), StoreType.PKCS12);
										temporary.set(selectedItem.getAlias(), keystore.getKeyStore().getPrivateKey(selectedItem.getAlias()), keystore.getKeyStore().getChain(selectedItem.getAlias()), null);
										OutputStream output = new BufferedOutputStream(new FileOutputStream(file));
										try {
											temporary.save(output, keystore.getKeyStore().getPassword());
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
		generatePKCS10.addEventHandler(MouseEvent.MOUSE_CLICKED, new EventHandler<MouseEvent>() {
			@SuppressWarnings({ "unchecked", "rawtypes" })
			@Override
			public void handle(MouseEvent arg0) {
				KeyStoreEntry selectedItem = table.getSelectionModel().getSelectedItem();
				if (selectedItem != null && "Private Key".equals(selectedItem.getType())) {
					SimpleProperty<File> fileProperty = new SimpleProperty<File>("File", File.class, true);
					SimpleProperty<SignatureType> signatureProperty = new SimpleProperty<SignatureType>("Signature Type", SignatureType.class, true);
					Set properties = new LinkedHashSet(Arrays.asList(new Property [] { fileProperty, signatureProperty }));
					
					final SimplePropertyUpdater updater = new SimplePropertyUpdater(true, properties, 
						new ValueImpl<File>(fileProperty, new File(selectedItem.getAlias() + ".pkcs10")),
						new ValueImpl<SignatureType>(signatureProperty, SignatureType.SHA256WITHRSA)
					);
					EAIDeveloperUtils.buildPopup(MainController.getInstance(), updater, "Generate PKCS10 for " + selectedItem.getAlias(), new EventHandler<MouseEvent>() {
						@Override
						public void handle(MouseEvent arg0) {
							File file = updater.getValue("File");
							SignatureType type = updater.getValue("Signature Type");
							if (type == null) {
								type = SignatureType.SHA256WITHRSA;
							}
							if (file != null) {
								try {
									PrivateKey privateKey = (PrivateKey) keystore.getKeyStore().getPrivateKey(selectedItem.getAlias());
									PublicKey publicKey = keystore.getKeyStore().getChain(selectedItem.getAlias())[0].getPublicKey();
									KeyPair pair = new KeyPair(publicKey, privateKey);
									byte[] generatePKCS10 = BCSecurityUtils.generatePKCS10(pair, type, keystore.getKeyStore().getChain(selectedItem.getAlias())[0].getSubjectX500Principal());
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
		
		Button signPKCS10 = new Button("Sign PKCS10");
		signPKCS10.addEventHandler(MouseEvent.MOUSE_CLICKED, new EventHandler<MouseEvent>() {
			@SuppressWarnings({ "unchecked", "rawtypes" })
			@Override
			public void handle(MouseEvent arg0) {
				KeyStoreEntry selectedItem = table.getSelectionModel().getSelectedItem();
				if (selectedItem != null && "Private Key".equals(selectedItem.getType())) {
					SimpleProperty<String> aliasProperty = new SimpleProperty<String>("Alias", String.class, false);
					SimpleProperty<byte[]> contentProperty = new SimpleProperty<byte[]>("PKCS10", byte[].class, true);
					SimpleProperty<Duration> durationProperty = new SimpleProperty<Duration>("Duration", Duration.class, false);
					SimpleProperty<SignatureType> signatureProperty = new SimpleProperty<SignatureType>("Signature Type", SignatureType.class, true);
					Set properties = new LinkedHashSet(Arrays.asList(new Property [] { aliasProperty, contentProperty, durationProperty, signatureProperty }));
					
					final SimplePropertyUpdater updater = new SimplePropertyUpdater(true, properties);
					EAIDeveloperUtils.buildPopup(MainController.getInstance(), updater, "Sign PKCS10 using " + selectedItem.getAlias(), new EventHandler<MouseEvent>() {
						@Override
						public void handle(MouseEvent arg0) {
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
		
		final Button showPassword = new Button("Show Password");
		showPassword.addEventHandler(MouseEvent.MOUSE_CLICKED, new EventHandler<MouseEvent>() {
			@SuppressWarnings({ "unchecked", "rawtypes" })
			@Override
			public void handle(MouseEvent arg0) {
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
		
		final Button addChain = new Button("Add Key Chain");
		addChain.addEventHandler(MouseEvent.MOUSE_CLICKED, new EventHandler<MouseEvent>() {
			@SuppressWarnings({ "unchecked", "rawtypes" })
			@Override
			public void handle(MouseEvent arg0) {
				final KeyStoreEntry selectedItem = table.getSelectionModel().getSelectedItem();
				if (selectedItem != null && "Private Key".equals(selectedItem.getType())) {
					SimpleProperty<Integer> amountOfCertificatesProperty = new SimpleProperty<Integer>("Amount Of Certificates", Integer.class, true);
					final SimplePropertyUpdater chooseAmountUpdater = new SimplePropertyUpdater(true, new LinkedHashSet(Arrays.asList(new Property [] { amountOfCertificatesProperty })));
					EAIDeveloperUtils.buildPopup(MainController.getInstance(), chooseAmountUpdater, "Amount of certificates in chain", new EventHandler<MouseEvent>() {
						@Override
						public void handle(MouseEvent arg0) {
							int amountOfCertificates = chooseAmountUpdater.getValue("Amount Of Certificates");
							SimpleProperty<String> aliasProperty = new SimpleProperty<String>("Alias", String.class, false);
							SimpleProperty<String> passwordProperty = new SimpleProperty<String>("Password", String.class, false);
							Set properties = new LinkedHashSet(Arrays.asList(new Property [] { aliasProperty, passwordProperty }));
							for (int i = 0; i < amountOfCertificates; i++) {
								SimpleProperty<byte[]> certificateProperty = new SimpleProperty<byte[]>("Certificate[" + i + "]", byte[].class, true);
								properties.add(certificateProperty);
							}
							final SimplePropertyUpdater updater = new SimplePropertyUpdater(true, properties);
							EAIDeveloperUtils.buildPopup(MainController.getInstance(), updater, "Add new chain to private key " + selectedItem.getAlias(), new EventHandler<MouseEvent>() {
								@Override
								public void handle(MouseEvent arg0) {
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
										PrivateKey privateKey = (PrivateKey) keystore.getKeyStore().getPrivateKey(selectedItem.getAlias());
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
			}
		});

		buttons.getChildren().addAll(newSelfSigned, download, addCertificate, addKeystore, rename, delete, generatePKCS10, signPKCS10, showPassword, addChain);
		vbox.getChildren().addAll(buttons, table);
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
		Enumeration<String> aliases = keystore.getKeyStore().aliases();
		while (aliases.hasMoreElements()) {
			String alias = aliases.nextElement();
			KeyStoreEntry entry = new KeyStoreEntry();
			entry.setAlias(alias);

			X509Certificate certificate = null;
			// a certificate
			if (keystore.getKeyStore().entryInstanceOf(alias, KeyStore.TrustedCertificateEntry.class)) {
				certificate = keystore.getCertificate(alias);
				entry.setType("Certificate");
			}
			else if (keystore.getKeyStore().entryInstanceOf(alias, KeyStore.PrivateKeyEntry.class)) {
				X509Certificate[] chain = keystore.getChain(alias);
				certificate = chain[0];
				entry.setChainLength(chain.length);
				entry.setType("Private Key");
			}
			else if (keystore.getKeyStore().entryInstanceOf(alias, KeyStore.SecretKeyEntry.class)) {
				entry.setType("Secret Key");
			}
			else {
				entry.setType("Unknown");
			}
			if (certificate != null) {
				entry.setIssuer(certificate.getIssuerX500Principal().toString());
				entry.setSubject(certificate.getSubjectX500Principal().toString());
				entry.setNotAfter(certificate.getNotAfter());
				entry.setNotBefore(certificate.getNotBefore());
			}
			entries.add(entry);
		}
		return entries;
	}

	@Override
	protected List<Property<?>> getCreateProperties() {
		return Arrays.asList(new SimpleProperty<String>("Password", String.class, true));
	}

	@Override
	protected BaseArtifactGUIInstance<KeyStoreArtifact> newGUIInstance(Entry entry) {
		return new BaseArtifactGUIInstance<KeyStoreArtifact>(this, (ResourceEntry) entry);
	}

	@Override
	protected KeyStoreArtifact newInstance(MainController controller, RepositoryEntry entry, Value<?>...values) throws IOException {
		KeyStoreArtifact keystore = new KeyStoreArtifact(entry.getId(), entry.getContainer());
		keystore.create(getValue("Password", String.class, values));
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
