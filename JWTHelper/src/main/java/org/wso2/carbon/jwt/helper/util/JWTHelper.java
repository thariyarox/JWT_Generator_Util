package org.wso2.carbon.jwt.helper.util;

import org.apache.axiom.util.base64.Base64Utils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.base.MultitenantConstants;
import org.wso2.carbon.context.CarbonContext;
import org.wso2.carbon.core.util.KeyStoreManager;
import org.wso2.carbon.jwt.helper.JWTHelperDataHolder;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.core.service.RealmService;

import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.util.Calendar;
import java.util.concurrent.ConcurrentHashMap;

public class JWTHelper {

    private static Log log = LogFactory.getLog(JWTHelper.class);

    private static final String SHA256_WITH_RSA = "SHA256withRSA";
    private static String signatureAlgorithm = SHA256_WITH_RSA;
    private static final String NONE = "NONE";
    private static volatile long ttl = -1L;

    private static ConcurrentHashMap<Integer, Key> privateKeys = new ConcurrentHashMap<Integer, Key>();
    private static ConcurrentHashMap<Integer, Certificate> publicCerts = new ConcurrentHashMap<Integer, Certificate>();

    /**
     * Method exposed to outside for generateing the JWT.
     *
     * @return signed JWT token
     * @throws Exception
     */
    public static String generateJWT() throws Exception {

        String jwt = buildJWT(CarbonContext.getThreadLocalCarbonContext().getTenantDomain());

        if(log.isDebugEnabled()) {
            log.debug("JWT Generated : " + jwt);
        }

        return jwt;
    }


    /**
     * Method that generates the JWT.
     *
     * @return signed JWT token
     * @throws Exception
     */
    private static String buildJWT(String tenantDomain) throws Exception {

        //generating expiring timestamp
        long currentTime = Calendar.getInstance().getTimeInMillis();
        long expireIn = currentTime + 1000 * 60 * getTTL();

        String jwtBody;
        String issuer = "wso2.org/appserver";
        int tenantId = getTenantId(tenantDomain);

        //Sample JWT body
        //{"iss":"wso2.org/appserver","exp":1448299984841,"tenant_domain":"wso2.com","tenant_id":"1"}

        StringBuilder jwtBuilder = new StringBuilder();
        jwtBuilder.append("{");
        jwtBuilder.append("\"iss\":\"");
        jwtBuilder.append(issuer);
        jwtBuilder.append("\",");

        jwtBuilder.append("\"exp\":");
        jwtBuilder.append(String.valueOf(expireIn));
        jwtBuilder.append(",");

        jwtBuilder.append("\"tenant_domain\":\"");
        jwtBuilder.append(tenantDomain);
        jwtBuilder.append("\",");

        jwtBuilder.append("\"http://wso2.org/claims/enduserTenantId\":\"");
        jwtBuilder.append(String.valueOf(tenantId));
        jwtBuilder.append("\"");

        jwtBuilder.append("}");
        jwtBody = jwtBuilder.toString();

        String jwtHeader = null;

        //if signature algo==NONE, header without cert
        if (signatureAlgorithm.equals(NONE)) {
            jwtHeader = "{\"typ\":\"JWT\"}";
        } else if (signatureAlgorithm.equals(SHA256_WITH_RSA)) {
            jwtHeader = addCertToHeader(tenantDomain);
        }

        String base64EncodedHeader = Base64Utils.encode(jwtHeader.getBytes());
        String base64EncodedBody = Base64Utils.encode(jwtBody.getBytes());
        if (signatureAlgorithm.equals(SHA256_WITH_RSA)) {
            String assertion = base64EncodedHeader + "." + base64EncodedBody;

            //get the assertion signed
            byte[] signedAssertion = signJWT(assertion, tenantDomain);


            if(log.isDebugEnabled()) {
                log.debug("Signed assertion value : " + new String(signedAssertion, "UTF-8"));
            }
            String base64EncodedAssertion = Base64Utils.encode(signedAssertion);

            return base64EncodedHeader + "." + base64EncodedBody + "." + base64EncodedAssertion;
        } else {
            return base64EncodedHeader + "." + base64EncodedBody + ".";
        }
    }

    private static long getTTL() {
        if (ttl != -1) {
            return ttl;
        }

        synchronized (JWTHelper.class) {
            if (ttl != -1) {
                return ttl;
            }
            String ttlValue = "15"; //This can be read from a property
            if (ttlValue != null) {
                ttl = Long.parseLong(ttlValue);
            } else {
                ttl = 15L;
            }
            return ttl;
        }
    }


    private static byte[] signJWT(String assertion, String tenantDomain) throws Exception {

        try {
            //get tenantId
            int tenantId = getTenantId(tenantDomain);

            Key privateKey = null;

            if (!(privateKeys.containsKey(tenantId))) {
                //get tenant's key store manager
                KeyStoreManager tenantKSM = KeyStoreManager.getInstance(tenantId);

                if (!tenantDomain.equals(MultitenantConstants.SUPER_TENANT_DOMAIN_NAME)) {
                    //derive key store name
                    String ksName = tenantDomain.trim().replace(".", "-");
                    String jksName = ksName + ".jks";
                    //obtain private key
                    //TODO: maintain a hash map with tenants' private keys after first initialization
                    privateKey = tenantKSM.getPrivateKey(jksName, tenantDomain);
                } else {
                    try {
                        privateKey = tenantKSM.getDefaultPrivateKey();
                    } catch (Exception e) {
                        log.error("Error while obtaining private key for super tenant", e);
                    }
                }
                if (privateKey != null) {
                    privateKeys.put(tenantId, privateKey);
                }
            } else {
                privateKey = privateKeys.get(tenantId);
            }

            //initialize signature with private key and algorithm
            Signature signature = Signature.getInstance(signatureAlgorithm);
            signature.initSign((PrivateKey) privateKey);

            //update signature with data to be signed
            byte[] dataInBytes = assertion.getBytes();
            signature.update(dataInBytes);

            //sign the assertion and return the signature
            byte[] signedInfo = signature.sign();
            return signedInfo;

        } catch (NoSuchAlgorithmException e) {
            String error = "Signature algorithm not found.";
            //do not log
            throw new Exception(error);
        } catch (InvalidKeyException e) {
            String error = "Invalid private key provided for the signature";
            //do not log
            throw new Exception(error);
        } catch (SignatureException e) {
            String error = "Error in signature";
            //do not log
            throw new Exception(error);
        } catch (Exception e) {
            //do not log
            throw new Exception(e.getMessage());
        }
    }

    private static int getTenantId(String tenantDomain) throws Exception {

        try {
            RealmService realmService = JWTHelperDataHolder.getInstance().getRealmService();
            int tenantId = realmService.getTenantManager().getTenantId(tenantDomain);
            return tenantId;
        } catch (UserStoreException e) {
            String error = "Error in obtaining tenantId from Domain";
            //do not log
            throw new Exception(error);
        }
    }

    /**
     * Helper method to add public certificate to JWT_HEADER to signature verification.
     *
     * @param endUserName
     * @throws Exception
     */
    private static String addCertToHeader(String tenantDomain) throws Exception {

        try {
            //get tenantId
            int tenantId = getTenantId(tenantDomain);
            Certificate publicCert = null;

            if (!(publicCerts.containsKey(tenantId))) {
                //get tenant's key store manager
                KeyStoreManager tenantKSM = KeyStoreManager.getInstance(tenantId);

                KeyStore keyStore = null;
                if (!tenantDomain.equals(MultitenantConstants.SUPER_TENANT_DOMAIN_NAME)) {
                    //derive key store name
                    String ksName = tenantDomain.trim().replace(".", "-");
                    String jksName = ksName + ".jks";
                    keyStore = tenantKSM.getKeyStore(jksName);
                    publicCert = keyStore.getCertificate(tenantDomain);
                } else {
                    publicCert = tenantKSM.getDefaultPrimaryCertificate();
                }
                if (publicCert != null) {
                    publicCerts.put(tenantId, publicCert);
                }
            } else {
                publicCert = publicCerts.get(tenantId);
            }

            //generate the SHA-1 thumbprint of the certificate
            //TODO: maintain a hashmap with tenants' pubkey thumbprints after first initialization
            MessageDigest digestValue = MessageDigest.getInstance("SHA-1");
            byte[] der = publicCert.getEncoded();
            digestValue.update(der);
            byte[] digestInBytes = digestValue.digest();

            String publicCertThumbprint = hexify(digestInBytes);
            String base64EncodedThumbPrint = Base64Utils.encode(publicCertThumbprint.getBytes());

            StringBuilder jwtHeader = new StringBuilder();

            //Sample header
            //{"typ":"JWT", "alg":"SHA256withRSA", "x5t":"NmJmOGUxMzZlYjM2ZDRhNTZlYTA1YzdhZTRiOWE0NWI2M2JmOTc1ZA=="}

            jwtHeader.append("{\"typ\":\"JWT\",");
            jwtHeader.append("\"alg\":\"");
            jwtHeader.append(signatureAlgorithm);
            jwtHeader.append("\",");

            jwtHeader.append("\"x5t\":\"");
            jwtHeader.append(base64EncodedThumbPrint);
            jwtHeader.append("\"");

            jwtHeader.append("}");
            return jwtHeader.toString();

        } catch (KeyStoreException e) {
            String error = "Error in obtaining tenant's keystore";
            throw new Exception(error);
        } catch (CertificateEncodingException e) {
            String error = "Error in generating public cert thumbprint";
            throw new Exception(error);
        } catch (NoSuchAlgorithmException e) {
            String error = "Error in generating public cert thumbprint";
            throw new Exception(error);
        } catch (Exception e) {
            String error = "Error in obtaining tenant's keystore";
            throw new Exception(error);
        }
    }

    /**
     * Helper method to hexify a byte array.
     *
     * @param bytes
     * @return hexadecimal representation
     */
    private static String hexify(byte bytes[]) {

        char[] hexDigits = {'0', '1', '2', '3', '4', '5', '6', '7',
                '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

        StringBuffer buf = new StringBuffer(bytes.length * 2);

        for (int i = 0; i < bytes.length; ++i) {
            buf.append(hexDigits[(bytes[i] & 0xf0) >> 4]);
            buf.append(hexDigits[bytes[i] & 0x0f]);
        }

        return buf.toString();
    }

}
