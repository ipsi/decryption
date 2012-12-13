package com.example;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.CertStore;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.X509Certificate;
import java.security.spec.EncodedKeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.Properties;

import javax.activation.CommandMap;
import javax.activation.MailcapCommandMap;
import javax.mail.BodyPart;
import javax.mail.Multipart;
import javax.mail.internet.MimeBodyPart;
import javax.mail.internet.MimeMessage;
import javax.mail.internet.MimeMultipart;

import org.bouncycastle.cms.RecipientId;
import org.bouncycastle.cms.RecipientInformation;
import org.bouncycastle.cms.RecipientInformationStore;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.mail.smime.SMIMEEnveloped;
import org.bouncycastle.mail.smime.SMIMEException;
import org.bouncycastle.mail.smime.SMIMESigned;
import org.bouncycastle.mail.smime.SMIMEUtil;

public class Decrypt {

	private static final String	KEY_ALGORITHM	= "RSA";

	private static String		PUBLIC_KEY_FILE;
	private static String		PRIVATE_KEY_FILE;

	private static PrivateKey	privateKey		= null;

	private static KeyFactory	keyFactory		= null;

	public static void main(String[] args) throws IOException, GeneralSecurityException {
		PUBLIC_KEY_FILE = "/signature_public_key.pem";
		PRIVATE_KEY_FILE = "/encryption_private_key.der";

		MailcapCommandMap mailcap = (MailcapCommandMap) CommandMap.getDefaultCommandMap();
		mailcap.addMailcap("application/pkcs7-signature;; x-java-content-handler=org.bouncycastle.mail.smime.handlers.pkcs7_signature");
		mailcap.addMailcap("application/pkcs7-mime;; x-java-content-handler=org.bouncycastle.mail.smime.handlers.pkcs7_mime");
		mailcap.addMailcap("application/x-pkcs7-signature;; x-java-content-handler=org.bouncycastle.mail.smime.handlers.x_pkcs7_signature");
		mailcap.addMailcap("application/x-pkcs7-mime;; x-java-content-handler=org.bouncycastle.mail.smime.handlers.x_pkcs7_mime");
		mailcap.addMailcap("multipart/signed;; x-java-content-handler=org.bouncycastle.mail.smime.handlers.multipart_signed");

		CommandMap.setDefaultCommandMap(mailcap);

		Security.addProvider(new BouncyCastleProvider());

		InputStream privateKeyFile = Decrypt.class.getResourceAsStream(PRIVATE_KEY_FILE);
		int available = privateKeyFile.available();
		byte[] privateKeyValue = new byte[available];
		privateKeyFile.read(privateKeyValue);

		EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(privateKeyValue);
		privateKey = getKeyFactory().generatePrivate(privateKeySpec);

		try {
			final InputStream inputStream = Decrypt.class.getResourceAsStream("/encrypted_file.dat");
			ByteArrayOutputStream bytemsg = new ByteArrayOutputStream();

			int numBytes;
			byte[] encryptedData = new byte[256];

			while ((numBytes = inputStream.read(encryptedData)) != -1)
				bytemsg.write(encryptedData, 0, numBytes);

			bytemsg.flush();

			encryptedData = bytemsg.toByteArray();

			Properties props = System.getProperties();
			javax.mail.Session session = javax.mail.Session.getDefaultInstance(props);

			// Load the encrypted message from the file
			// MimeMessage encryptedMime = new MimeMessage(session, new ByteArrayInputStream(encryptedData));
			MimeMessage encryptedMime = new MimeMessage(session);

			encryptedMime.setContent(new ByteArrayInputStream(encryptedData), "application/pkcs7-mime; name=\"smime.p7m\"; smime-type=enveloped-data");

			// Print out some stats about the message

			// Extract/decrypt the message body
			SMIMEEnveloped m = new SMIMEEnveloped(encryptedMime);

			AlgorithmParameters algoParams = m.getEncryptionAlgorithmParameters("BC");

			RecipientInformationStore recipients = m.getRecipientInfos();
			RecipientInformation recipient = (RecipientInformation) recipients.getRecipients().toArray()[0];
			RecipientId rid = recipient.getRID();

			MimeBodyPart res = SMIMEUtil.toMimeBodyPart(recipient.getContent(privateKey, "BC"));

			SMIMESigned s = new SMIMESigned((MimeMultipart) res.getContent());

			if (verify(s)) {
				// return (String)content.getContent();
			}
			else {
				// throw new SMIMEException("Error evaluating the signature.");
			}

			//
			// extract the content
			//
			MimeBodyPart content = s.getContent();

			Object cont = content.getContent();

			if (cont instanceof String) {
				throw new SMIMEException("The content is not a MultiPart");
			}
			else if (cont instanceof Multipart) {
				Multipart mp = (Multipart) cont;
				int count = mp.getCount();
				for (int i = 0; i < count; i++) {
					BodyPart bp = mp.getBodyPart(i);
					Object part = bp.getContent();

					if (part instanceof String) {
						System.out.println("Decryped Message:");
						System.out.println(part);
					}
					else
						throw new SMIMEException("Error evaluating the part of the MultiPart during decryption.");
				}
			}

			// Display the decrypted content

			// return (String)res.getContent();
			// return (String)content.getContent();
		}
		catch (Exception e) {
			e.printStackTrace();
		}
	}

	public static X509Certificate getCertificate() throws FileNotFoundException, IOException, CertificateException, java.security.NoSuchProviderException {
		InputStream inStream = Decrypt.class.getResourceAsStream(PUBLIC_KEY_FILE);
		CertificateFactory cf = CertificateFactory.getInstance("X.509", "BC");
		X509Certificate cert = (X509Certificate) cf.generateCertificate(inStream);
		inStream.close();

		return cert;
	}

	private static boolean verify(SMIMESigned s) throws Exception {
		/* Add the list of certs to the generator */
		ArrayList certList = new ArrayList();
		certList.add(getCertificate());
		CertStore certs = CertStore.getInstance("Collection", new CollectionCertStoreParameters(certList), "BC");
		// signer.addCertificatesAndCRLs(certs);

		/* certificates and crls passed in the signature */
		certs = s.getCertificatesAndCRLs("Collection", "BC");

		/* SignerInfo blocks which contain the signatures */
		SignerInformationStore signers = s.getSignerInfos();

		Collection c = signers.getSigners();
		Iterator it = c.iterator();

		/* check each signer */
		while (it.hasNext()) {
			SignerInformation signer = (SignerInformation) it.next();
			Collection certCollection = certs.getCertificates(signer.getSID());

			Iterator certIt = certCollection.iterator();
			X509Certificate cert = (X509Certificate) certIt.next();

			/* verify that the sig is correct and that it was generated */
			/* when the certificate was current */
			if (signer.verify(cert, "BC")) {
				return true;
			}
			else {
				return false;
			}
		}

		return false;
	}

	private static KeyFactory getKeyFactory() throws NoSuchAlgorithmException {
		if (keyFactory == null) {
			keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
		}

		return keyFactory;
	}
}
