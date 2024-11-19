package com.stupica.httpClient;


import com.stupica.ConstGlobal;
import com.stupica.ConstWeb;
import com.stupica.GlobalVar;
import com.stupica.core.UtilString;

import javax.net.ssl.*;
import java.io.*;
import java.net.HttpURLConnection;
import java.net.SocketTimeoutException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.logging.Logger;

import static com.stupica.ConstWeb.*;


public class ClientHttpBase {

    protected boolean           bAddRefererParam = true;
    protected boolean           bAddOriginParam = false;
    protected boolean           bIsJsonRequest = true;
    protected boolean           bFunctionalityFollowRedirect = false;
    protected boolean           bFunctionalitySSLTrustAll = false;
    protected boolean           bReadHeaderResponse = true;

    protected final int         iTimeoutConnectDefault = 3600;
    protected final int         iTimeoutResponseReadDefault = 9000;
    protected int               iTimeoutConnect = 0;
    protected int               iTimeoutResponseRead = 0;

    protected int               iRedirectMax = 2;

    protected int               iLengthMaxResponseLog = 1024 * 2;

    protected long              iCountRequest = 0L;

    protected String            sUserAgent = null;
    protected final String      sUserAgentMozillaDef = "Mozilla/5.0";

    protected String            sURL = "http://localhost:8080";
    protected String            sReferer = "http://localhost:8080";
    protected String            sOrigin = "http://localhost";
    protected String            sSslContextProtocol = "SSL";    // SSL, TLS, ..

    protected String            sAuthHeaderValue = null;

    private URL                 objUrl = null;
    private HttpURLConnection   objConn = null;
    private SSLContext          objContextSec = null;

    private static Logger logger = Logger.getLogger(ClientHttpBase.class.getName());


    public ClientHttpBase() {
        init();
    }


    protected void init() {
        if (bFunctionalitySSLTrustAll) {
            trustEveryone();
        }
        if (bAddOriginParam) System.setProperty("sun.net.http.allowRestrictedHeaders", "true");
    }


    /**
     * Reference info:
     * If after all these you get an error message of HelloRequest followed by an unexpected handshake message
     * .. then set the following system property:
     * -> System.setProperty("sun.security.ssl.allowUnsafeRenegotiation", "true");
     */
    private void trustEveryone() {
        SSLContext context = null;

        try {
            HttpsURLConnection.setDefaultHostnameVerifier(new HostnameVerifier() {
                public boolean verify(String hostname, SSLSession session) {
                    logger.info("trustEveryone(): verify(): Check for Host: " + hostname);
                    return true;
                }});
            //context = SSLContext.getDefault();
            context = SSLContext.getInstance(sSslContextProtocol);
            context.init(null, new X509TrustManager[]{new X509TrustManager() {
                public void checkClientTrusted(X509Certificate[] chain,
                                               String authType) throws CertificateException {}
                public void checkServerTrusted(X509Certificate[] chain,
                                               String authType) throws CertificateException {}
                public X509Certificate[] getAcceptedIssuers() {
                    return new X509Certificate[0];
                }}}, new SecureRandom());
            HttpsURLConnection.setDefaultSSLSocketFactory(context.getSocketFactory());
        } catch (Exception e) { // should never happen
            logger.severe("trustEveryone(): Error .. Msg.: " + e.getMessage());
            if (GlobalVar.bIsModeVerbose)
                e.printStackTrace();
        }
    }


    /**
     * Reference info:
     * https://stackoverflow.com/questions/21223084/how-do-i-use-an-ssl-client-certificate-with-apache-httpclient
     *
     * Option is also:
     *         System.setProperty("javax.net.ssl.keyStore", "./TsaSrb_TestKorisnik.p12");
     *         System.setProperty("javax.net.ssl.keyStorePassword", "1234");
     *         System.setProperty("javax.net.ssl.keyStoreType", "pkcs12");
     */
    public int setKeyStore(InputStream aobjKeyStream, String asKeystoreType, char[] asKeyStorePassword, char[] asKeyPassword) {
        return setKeyTrustStore(aobjKeyStream, asKeystoreType, asKeyStorePassword, asKeyPassword, null, null);
    }

    /**
     * Reference info:
     * https://stackoverflow.com/questions/39578653/httpsurlconnection-using-keystore-instead-of-truststore-with-websphere-liberty-p#39581419
     */
    public int setKeyTrustStore(InputStream aobjKeyStream, String asKeystoreType, char[] asKeyStorePassword, char[] asKeyPassword,
                                InputStream aobjTrustStream, char[] asTrustStorePassword) {
        // Local variables
        int                 iResult;
        TrustManager[]      trustManagers = null;
        KeyManager[]        keyManagers = null;

        // Initialization
        iResult = ConstGlobal.RETURN_OK;

        if (bFunctionalitySSLTrustAll) {
            iResult = ConstGlobal.RETURN_WARNING;
            logger.warning("setKeyTrustStore(): Functionality: SSL_TrustAll is ON! This is NOT Supported!");
        }

        // Check previous step
        if (iResult == ConstGlobal.RETURN_OK) {
            if ((aobjTrustStream != null) && (asTrustStorePassword != null)) {
                trustManagers = buildTrustManager(aobjTrustStream, asTrustStorePassword);
            }
        }
        // Check previous step
        if (iResult == ConstGlobal.RETURN_OK) {
            if ((aobjKeyStream != null) && (asKeyStorePassword != null)) {
                if (asKeyPassword == null) {
                    logger.warning("setKeyTrustStore(): Key PSW NOT set! Assuming the same as KeyStorePSW.");
                }
                keyManagers = buildKeyManager(aobjKeyStream, asKeystoreType, asKeyStorePassword, asKeyPassword);
            }
        }

        // Check previous step
        if (iResult == ConstGlobal.RETURN_OK) {
            if ((trustManagers != null) || (keyManagers != null))
                try {
                    //context = SSLContext.getDefault();
                    objContextSec = SSLContext.getInstance(sSslContextProtocol);
                } catch (NoSuchAlgorithmException e) {
                    iResult = ConstGlobal.RETURN_ERROR;
                    logger.severe("setKeyTrustStore(): Error .. Msg.: " + e.getMessage());
                    if (GlobalVar.bIsModeVerbose)
                        e.printStackTrace();
                }
        }
        // Check previous step
        if (iResult == ConstGlobal.RETURN_OK) {
            if (objContextSec != null) {
                try {
                    objContextSec.init(keyManagers, trustManagers, new SecureRandom());
                } catch (KeyManagementException e) {
                    iResult = ConstGlobal.RETURN_ERROR;
                    logger.severe("setKeyTrustStore(): Error .. Msg.: " + e.getMessage());
                    if (GlobalVar.bIsModeVerbose)
                        e.printStackTrace();
                }
                SSLContext.setDefault(objContextSec);
            }
        }
        return iResult;
    }


    protected KeyManager[] buildKeyManager(InputStream aobjKeyStream, String asKeystoreType, char[] asKeyStorePassword, char[] asKeyPassword) {
        // Local variables
        int                 iResult;
        char[]              sKeyPassword = asKeyPassword;
        String              sKeystoreType = asKeystoreType;
        KeyManagerFactory   keyFactory = null;
        KeyManager[]        keyManagers = null;
        KeyStore        keyStore = null;

        // Initialization
        iResult = ConstGlobal.RETURN_OK;
        if (sKeyPassword == null)
            sKeyPassword = asKeyStorePassword;
        if (UtilString.isEmpty(sKeystoreType))
            sKeystoreType = KeyStore.getDefaultType();

        // Check previous step
        if (iResult == ConstGlobal.RETURN_OK) {
            try {
                keyStore = KeyStore.getInstance(sKeystoreType);
            } catch (KeyStoreException e) {
                iResult = ConstGlobal.RETURN_ERROR;
                logger.severe("buildKeyManager(): Error .. Msg.: " + e.getMessage());
                if (GlobalVar.bIsModeVerbose) {
                    e.printStackTrace();
                }
            }
        }

        // Check previous step
        if (iResult == ConstGlobal.RETURN_OK) {
            if (keyStore != null)
                try {
                    keyStore.load(aobjKeyStream, asKeyStorePassword);
                } catch (IOException e) {
                    iResult = ConstGlobal.RETURN_ERROR;
                    logger.severe("buildKeyManager(): Error .. Msg.: " + e.getMessage());
                } catch (NoSuchAlgorithmException e) {
                    iResult = ConstGlobal.RETURN_ERROR;
                    logger.severe("buildKeyManager(): Error .. Msg.: " + e.getMessage());
                } catch (CertificateException e) {
                    iResult = ConstGlobal.RETURN_ERROR;
                    logger.severe("buildKeyManager(): Error .. Msg.: " + e.getMessage());
                    if (GlobalVar.bIsModeVerbose)
                        e.printStackTrace();
                }
        }

        // Check previous step
        if (iResult == ConstGlobal.RETURN_OK) {
            if (keyStore != null)
                try {
                    keyFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
                } catch (NoSuchAlgorithmException e) {
                    iResult = ConstGlobal.RETURN_ERROR;
                    logger.severe("buildKeyManager(): Error .. Msg.: " + e.getMessage());
                    if (GlobalVar.bIsModeVerbose)
                        e.printStackTrace();
                }
        }

        // Check previous step
        if (iResult == ConstGlobal.RETURN_OK) {
            if (keyFactory != null)
                try {
                    keyFactory.init(keyStore, sKeyPassword);
                } catch (KeyStoreException e) {
                    iResult = ConstGlobal.RETURN_ERROR;
                    logger.severe("buildKeyManager(): Error .. Msg.: " + e.getMessage());
                    if (GlobalVar.bIsModeVerbose)
                        e.printStackTrace();
                } catch (NoSuchAlgorithmException e) {
                    iResult = ConstGlobal.RETURN_ERROR;
                    logger.severe("buildKeyManager(): Error .. Msg.: " + e.getMessage());
                } catch (UnrecoverableKeyException e) {
                    iResult = ConstGlobal.RETURN_ERROR;
                    logger.severe("buildKeyManager(): Error .. Msg.: " + e.getMessage());
                    if (GlobalVar.bIsModeVerbose)
                        e.printStackTrace();
                }
        }

        // Check previous step
        if (iResult == ConstGlobal.RETURN_OK) {
            if (keyFactory != null)
                keyManagers = keyFactory.getKeyManagers();
        }
        return keyManagers;
    }

    protected TrustManager[] buildTrustManager(InputStream aobjTrustStream, char[] asTrustStorePassword) {
        // Local variables
        int                 iResult;
        TrustManagerFactory trustManagerFactory = null;
        KeyStore            trustStore = null;
        TrustManager[]      trustManagers = null;

        // Initialization
        iResult = ConstGlobal.RETURN_OK;

        try {
            trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        } catch (NoSuchAlgorithmException e) {
            iResult = ConstGlobal.RETURN_ERROR;
            logger.severe("buildTrustManager(): Error .. Msg.: " + e.getMessage());
            if (GlobalVar.bIsModeVerbose)
                e.printStackTrace();
        }
        // Check previous step
        if (iResult == ConstGlobal.RETURN_OK) {
            try {
                trustStore = KeyStore.getInstance(KeyStore.getDefaultType());
            } catch (KeyStoreException e) {
                iResult = ConstGlobal.RETURN_ERROR;
                logger.severe("buildTrustManager(): Error .. Msg.: " + e.getMessage());
                if (GlobalVar.bIsModeVerbose)
                    e.printStackTrace();
            }
        }
        // Check previous step
        if (iResult == ConstGlobal.RETURN_OK) {
            if (trustStore != null)
                try {
                    trustStore.load(aobjTrustStream, asTrustStorePassword);
                } catch (IOException e) {
                    iResult = ConstGlobal.RETURN_ERROR;
                    logger.severe("buildTrustManager(): Error .. Msg.: " + e.getMessage());
                    if (GlobalVar.bIsModeVerbose)
                        e.printStackTrace();
                } catch (NoSuchAlgorithmException e) {
                    iResult = ConstGlobal.RETURN_ERROR;
                    logger.severe("buildTrustManager(): Error .. Msg.: " + e.getMessage());
                    if (GlobalVar.bIsModeVerbose)
                        e.printStackTrace();
                } catch (CertificateException e) {
                    iResult = ConstGlobal.RETURN_ERROR;
                    logger.severe("buildTrustManager(): Error .. Msg.: " + e.getMessage());
                    if (GlobalVar.bIsModeVerbose)
                        e.printStackTrace();
                }
        }
        // Check previous step
        if (iResult == ConstGlobal.RETURN_OK) {
            if (trustManagerFactory != null)
                if (trustStore != null)
                    try {
                        trustManagerFactory.init(trustStore);
                    } catch (KeyStoreException e) {
                        iResult = ConstGlobal.RETURN_ERROR;
                        logger.severe("buildTrustManager(): Error .. Msg.: " + e.getMessage());
                        if (GlobalVar.bIsModeVerbose)
                            e.printStackTrace();
                    }
        }
        // Check previous step
        if (iResult == ConstGlobal.RETURN_OK) {
            if (trustManagerFactory != null)
                trustManagers = trustManagerFactory.getTrustManagers();
        } else
            trustManagers = null;
        return trustManagers;
    }


    public void setUrl(String asVal) {
        sURL = asVal;
    }

    public void setReferer(String asVal) {
        sReferer = asVal;
    }

    public void setTrustAll(boolean abVal) {
        bFunctionalitySSLTrustAll = abVal;
        if (bFunctionalitySSLTrustAll) {
            trustEveryone();
        }
    }

    public void setFollowRedirect(boolean abVal) {
        bFunctionalityFollowRedirect = abVal;
    }

    public void setJsonRequest(boolean abVal) {
        bIsJsonRequest = abVal;
    }

    public void setUserAgentMozillaDef() {
        sUserAgent = sUserAgentMozillaDef;
    }

    public void setBasicAuth(String asUser, String asPsw) {
        String sAuth;

        if ((asUser == null) && (asPsw == null))
            return;
        else if (asPsw == null)
            sAuth = asUser;
        else if (asUser == null)
            sAuth = ":" + asPsw;
        else
            sAuth = asUser + ":" + asPsw;
        if (sAuth != null) {
            byte[] encodedAuth = Base64.getEncoder().encode(sAuth.getBytes(StandardCharsets.UTF_8));
            sAuthHeaderValue = "Basic " + new String(encodedAuth);
        }
    }


    private int openConnection(String asUrl) {
        return openConnection(HTTP_METHOD_NAME_GET, asUrl, null, null);
    }

    private int openConnection(String asMethod, String asUrl, String asParam, byte[] aarrDataPayload) {
        // Local variables
        int                 iResult;
        long                iStartProcess = System.currentTimeMillis();
        long                iStopProcess = 0L;
        HttpsURLConnection  objConnSecure = null;

        // Initialization
        iResult = ConstGlobal.RETURN_OK;

        try {
            objUrl = new URL(asUrl);
        } catch (Exception ex) {
            iResult = ConstGlobal.RETURN_ERROR;
            logger.severe("openConnection(): URL is not in proper format/structure!"
                    + " URL: " + asUrl
                    + "; Msg.: " + ex.getMessage());
            if (GlobalVar.bIsModeVerbose)
                ex.printStackTrace();
        }
        // Check previous step
        if (iResult == ConstGlobal.RETURN_OK) {
            if (objConn == null) {
                setUrl(asUrl);
            }
            try {
                if (objContextSec != null) {
                    objConnSecure = (HttpsURLConnection) objUrl.openConnection();
                    objConnSecure.setSSLSocketFactory(objContextSec.getSocketFactory());
                    objConn = objConnSecure;
                } else
                    objConn = (HttpURLConnection) objUrl.openConnection();
            } catch (Exception ex) {
                iResult = ConstGlobal.RETURN_ERROR;
                iStopProcess = System.currentTimeMillis();
                logger.severe("openConnection(): Error at opening connection!!"
                        + " URL: " + asUrl
                        + "; ElapseTime(ms): " + (iStopProcess - iStartProcess)
                        + "; Msg.: " + ex.getMessage());
            }
        }
        // Check previous step
        if (iResult == ConstGlobal.RETURN_OK) {
            if (iTimeoutConnect == 0) iTimeoutConnect = iTimeoutConnectDefault;
            if (iTimeoutResponseRead == 0) iTimeoutResponseRead = iTimeoutResponseReadDefault;
            objConn.setConnectTimeout(iTimeoutConnect);
            objConn.setReadTimeout(iTimeoutResponseRead);
        }
        // Check previous step
        if (iResult == ConstGlobal.RETURN_OK) {
            try {
                objConn.setRequestMethod(asMethod);
            } catch (Exception ex) {
                iResult = ConstGlobal.RETURN_ERROR;
                logger.severe("openConnection(): Error at setting protocol!!"
                        + " URL: " + asUrl
                        + "; Msg.: " + ex.getMessage());
            }
        }

        // Check previous step
        if (iResult == ConstGlobal.RETURN_OK) {
            iResult = updateConnectionParam(objConn);
            // Error
            if (iResult != ConstGlobal.RETURN_OK) {
                iStopProcess = System.currentTimeMillis();
                logger.severe("openConnection(): Error at updateConnectionParam(conn) for service!"
                        + " URL: " + asUrl
                        + "; ElapseTime(ms): " + (iStopProcess - iStartProcess)
                        + "; iResult: " + iResult);
            }
        }
        // Check previous step
        if (iResult == ConstGlobal.RETURN_OK) {
            if (UtilString.isEmpty(asParam))
                iResult = updateConnectionParam(objConn, aarrDataPayload);
            else
                iResult = updateConnectionParam(objConn, asParam);
            // Error
            if (iResult != ConstGlobal.RETURN_OK) {
                iStopProcess = System.currentTimeMillis();
                logger.severe("openConnection(): Error at updateConnectionParam(conn, param/aarrDataPayload) for service!"
                        + " URL: " + asUrl
                        + "; ElapseTime(ms): " + (iStopProcess - iStartProcess)
                        + "; iResult: " + iResult);
            }
        }

        // Check previous step
        if (iResult == ConstGlobal.RETURN_OK) {
            try {
                objConn.connect();
            } catch (Exception ex) {
                iResult = ConstGlobal.RETURN_ERROR;
                iStopProcess = System.currentTimeMillis();
                logger.severe("openConnection(): Error at connecting to URL:Port!!"
                        + "\n\tURL: " + asUrl
                        + " :: Port: " + objUrl.getPort()
                        + "\n\tElapseTime(ms): " + (iStopProcess - iStartProcess)
                        + ";\tMsg.: " + ex.getMessage());
                if (GlobalVar.bIsModeVerbose)
                    ex.printStackTrace();
            }
        }
        return iResult;
    }

    public int closeConnection() {
        // Local variables
        int             iResult;

        // Initialization
        iResult = ConstGlobal.RETURN_OK;

        if (objConn != null) {
            objConn.disconnect();
        }
        return iResult;
    }


    private int updateConnectionParam(HttpURLConnection aobjConn, String asParam) {
        // Local variables
        int         iResult;

        // Initialization
        iResult = ConstGlobal.RETURN_OK;

        if (asParam != null) {
            iResult = updateConnectionParam(aobjConn, asParam.getBytes(StandardCharsets.UTF_8));
        }
        return iResult;
    }
    private int updateConnectionParam(HttpURLConnection aobjConn, byte[] aarrData) {
        // Local variables
        int         iResult;
        byte[]      arrDataPayload = aarrData;

        // Initialization
        iResult = ConstGlobal.RETURN_OK;

        if (arrDataPayload != null) {
            OutputStream        objOut = null;
            //DataOutputStream    objOut = null;
            //OutputStreamWriter  objOsw = null;

            try {
                //aobjConn.setRequestProperty("Referer", sReferer);
                aobjConn.setRequestProperty("Content-Length", Integer.toString(arrDataPayload.length));
                aobjConn.setDoOutput(true);
                objOut = new DataOutputStream(aobjConn.getOutputStream());

                //objOut.writeBytes(ParameterStringBuilder.getParamsString(parameters));

                //objOut = aobjConn.getOutputStream();
                //objOsw = new OutputStreamWriter(objOut, ConstGlobal.ENCODING_UTF_8);
                //objOsw.write(asParam);

                objOut.write(arrDataPayload);
                objOut.flush();
                //objOut.writeBytes(asParam);

                //objOsw.flush();
                //objOsw.close();
                objOut.close();  //don't forget to close the OutputStream
            } catch (IOException ex) {
                iResult = ConstGlobal.RETURN_ERROR;
                logger.severe("updateConnectionParam(): Error at setting HTTP Data/Payload!"
                        + " sURL: " + sURL
                        + "; ContentLen: " + arrDataPayload.length
                        + "; iResult: " + iResult
                        + "; Msg.: " + ex.getMessage());
                if (GlobalVar.bIsModeVerbose)
                    ex.printStackTrace();
            }
        }
        return iResult;
    }

    protected int updateConnectionParam(HttpURLConnection aobjConn) {
        // Local variables
        int             iResult;

        // Initialization
        iResult = ConstGlobal.RETURN_OK;

        try {
            if (bIsJsonRequest)
                aobjConn.setRequestProperty("Content-Type", "application/json");
            //aobjConn.setRequestProperty("Accept", "text/html,application/xhtml+xml,application/xml");
            if (!UtilString.isEmptyTrim(sUserAgent)) {
                aobjConn.setRequestProperty("User-Agent", sUserAgent);
            }
            //aobjConn.setRequestProperty("Accept-Charset", ConstGlobal.ENCODING_UTF_8);

            //logger.info("updateConnectionParam(): "
            //        + " bAddRefererParam: " + bAddRefererParam
            //        + "; sReferer: " + sReferer);
            if (bAddRefererParam) {
                aobjConn.setRequestProperty("Referer", sReferer);
            }
            //logger.info("updateConnectionParam(): "
            //        + " bAddOriginParam: " + bAddOriginParam
            //        + "; sOrigin: " + sOrigin);
            if (bAddOriginParam) {
                objConn.setRequestProperty("Origin", sOrigin);
                //objConn.setRequestProperty("Origin", "http://localhost:" + iPort);
            }
            if (bFunctionalityFollowRedirect) {
                objConn.setInstanceFollowRedirects(true);  // .. you still need to handle redirect manually;
                //HttpURLConnection.setFollowRedirects(true);
            }

            if (sAuthHeaderValue != null)
                objConn.setRequestProperty("Authorization", sAuthHeaderValue);
        } catch (Exception ex) {
            iResult = ConstGlobal.RETURN_ERROR;
            logger.severe("updateConnectionParam(): Error at setting HTTP Parameters!"
                    + " sURL: " + sURL
                    + "; iResult: " + iResult
                    + "; Msg.: " + ex.getMessage());
            if (GlobalVar.bIsModeVerbose)
                ex.printStackTrace();
        }
        return iResult;
    }


    protected ResultHttpStream testRequestForUrl(String asUrl) {
        // Local variables
        ResultHttpStream objResponse = new ResultHttpStream();

        // Initialization

        objResponse = getRequestForUrlAsStream(asUrl);
        closeConnection();
        return objResponse;
    }


    protected int redirectReConnect(String asUrlRedirect, ResultHttpStream aobjResponse) {
        // Local variables
        int             iResult;

        // Initialization
        iResult = ConstGlobal.RETURN_OK;

        closeConnection();

        aobjResponse.iRedirectCount++;
        if (iRedirectMax < aobjResponse.iRedirectCount) {
            iResult = ConstGlobal.RETURN_ERROR;
            logger.warning("redirectReConnect(): Too Many Redirect! ResponseCode: " + aobjResponse.iResult
                    + "\n\tUrl: " + asUrlRedirect
                    + "\n\tRedirectCount: " + aobjResponse.iRedirectCount
                    + "; RedirectMax: " + iRedirectMax
                    + "\n\tReferer: " + sReferer
                    + "\n\tiResult: " + iResult
                    + "\n\tMsg.: Too Many Redirect -> Redirect -> .. will NOT go!");
            return iResult;
        }

        if (GlobalVar.bIsModeVerbose) {
            logger.info("redirectReConnect(): Redirecting to .."
                    + " URL: " + aobjResponse.sUrlRedirectLocation
                    + "; Count: " + aobjResponse.iRedirectCount
                    + "; iResult: " + iResult);
        }
        iResult = openConnection(aobjResponse.sUrlRedirectLocation);
        // Error
        if (iResult != ConstGlobal.RETURN_OK) {
            logger.severe("redirectReConnect(): Error at connecting to service!"
                    + " URL: " + asUrlRedirect
                    + "; iResult: " + iResult);
        }

        // Check previous step
        if (iResult == ConstGlobal.RETURN_OK) {
            try {
                aobjResponse.iResult = objConn.getResponseCode();
                logger.fine("redirectReConnect(): Connection = Ok. ResponseCode: " + aobjResponse.iResult
                        + "; iResult: " + iResult);
            } catch (IOException ex) {
                iResult = ConstGlobal.RETURN_ERROR;
                logger.severe("redirectReConnect(): Error at getting HTTP Response!"
                        + " Url: " + aobjResponse.sUrlRedirectLocation
                        + "; iResponseHttp: " + aobjResponse.iResult
                        + "; iResult: " + iResult
                        + "; Msg.: " + ex.getMessage());
            }
            if (aobjResponse.iResult != ConstWeb.HTTP_RESP_OK) {
                if (aobjResponse.iResult == HttpURLConnection.HTTP_MOVED_TEMP
                        || aobjResponse.iResult == HttpURLConnection.HTTP_MOVED_PERM
                        || aobjResponse.iResult == HttpURLConnection.HTTP_SEE_OTHER) {
                    // Get new Location
                    aobjResponse.sUrlRedirectLocation = objConn.getHeaderField("Location");
                    // Redirect -> Redirect -> .. will NOT go!
//                    iResult = ConstGlobal.RETURN_ERROR;
//                    logger.warning("redirectReConnect(): Response = NOT Ok. ResponseCode: " + aobjResponse.iResult
//                            + "\n\tUrl: " + asUrlRedirect
//                            + "\n\tRedirectCount: " + aobjResponse.iRedirectCount
//                            + "\n\tReferer: " + sReferer
//                            + "\n\tiResult: " + iResult
//                            + "\n\tMsg.: Redirect -> Redirect -> .. will NOT go!");
                    iResult = redirectReConnect(aobjResponse.sUrlRedirectLocation, aobjResponse);
                    // Check previous step
                    if (iResult != ConstGlobal.RETURN_OK) {
                        logger.warning("redirectReConnect(): Error in method: redirectReConnect() - LOOP!"
                                + "\n\tUrl: " + asUrlRedirect
                                + "\n\tRedirectUrl: " + aobjResponse.sUrlRedirectLocation
                                + "\n\tRedirectCount: " + aobjResponse.iRedirectCount
                                + "\n\tReferer: " + sReferer
                                + "\n\tiResult: " + iResult);
                    }
                } else {
                    // NOT Cool .. but don't bother too much with 2xx response
                    if ((aobjResponse.iResult < ConstWeb.HTTP_RESP_OK) || (aobjResponse.iResult > (ConstWeb.HTTP_RESP_OK + 100))) {
                        iResult = ConstGlobal.RETURN_ERROR;
                        logger.warning("redirectReConnect(): Response = NOT Ok. ResponseCode: " + aobjResponse.iResult
                                + "\n\tUrl: " + asUrlRedirect
                                + "\n\tReferer: " + sReferer
                                + "\n\tiResult: " + iResult);
                    }
                }
            }
        }
        return iResult;
    }


    protected ResultHttpStream getRequestForUrlAsStream(String asUrl) {
        // Local variables
        int             iResult;
        ResultHttpStream objResponse = new ResultHttpStream();

        // Initialization
        iResult = ConstGlobal.RETURN_OK;
        iCountRequest++;

        // Check previous step
        if (iResult == ConstGlobal.RETURN_OK) {
            iResult = openConnection(asUrl);
            // Error
            if (iResult != ConstGlobal.RETURN_OK) {
                logger.severe("getRequestForUrlAsStream(): Error at connecting to service!"
                        + " URL: " + asUrl
                        + "; iResult: " + iResult);
            }
        }

        // Check previous step
        if (iResult == ConstGlobal.RETURN_OK) {
            try {
                objResponse.iResult = objConn.getResponseCode();
            } catch (IOException ex) {
                iResult = ConstGlobal.RETURN_ERROR;
                logger.severe("getRequestForUrlAsStream(): Error at getting HTTP Response!"
                        + " Url: " + asUrl
                        + "; iResponseHttp: " + objResponse.iResult
                        + "; iResult: " + iResult
                        + "; Msg.: " + ex.getMessage());
            }
            if (objResponse.iResult != ConstWeb.HTTP_RESP_OK) {
                if (bFunctionalityFollowRedirect) {
                    // Resource:
                    // https://stackoverflow.com/questions/1884230/urlconnection-doesnt-follow-redirect
                    //
                    if (objResponse.iResult == HttpURLConnection.HTTP_MOVED_TEMP
                            || objResponse.iResult == HttpURLConnection.HTTP_MOVED_PERM
                            || objResponse.iResult == HttpURLConnection.HTTP_SEE_OTHER) {
                        objResponse.bIsRedirect = true;
                        objResponse.sUrlRedirectLocation = objConn.getHeaderField("Location");
                        //objResponse.sUrlRedirectLocation = URLDecoder.decode(objResponse.sUrlRedirectLocation, ConstGlobal.ENCODING_UTF_8);
                        objResponse.sCookies = objConn.getHeaderField("Set-Cookie");
                    }
                } else {
                    // NOT Cool .. but don't bother too much with 2xx response
                    if ((objResponse.iResult < ConstWeb.HTTP_RESP_OK) || (objResponse.iResult > (ConstWeb.HTTP_RESP_OK + 100))) {
                        iResult = ConstGlobal.RETURN_ERROR;
                        logger.warning("getRequestForUrlAsStream(): Response = NOT Ok. ResponseCode: " + objResponse.iResult
                                + "\n\tUrl: " + asUrl
                                + "\n\tReferer: " + sReferer
                                + "\n\tiResult: " + iResult);
                    }
                }
            }
        }

        // Check previous step
        if (iResult == ConstGlobal.RETURN_OK) {
            if (objResponse.bIsRedirect) {
                iResult = redirectReConnect(objResponse.sUrlRedirectLocation, objResponse);
                // Check previous step
                if (iResult != ConstGlobal.RETURN_OK) {
                    logger.severe("getRequestForUrlAsStream(): Error in method: redirectReConnect()!"
                            + "\n\tUrl: " + asUrl
                            + "\n\tRedirectUrl: " + objResponse.sUrlRedirectLocation
                            + "\n\tRedirectCount: " + objResponse.iRedirectCount
                            + "\n\tReferer: " + sReferer
                            + "\n\tiResult: " + iResult);
                }
            }
        }

        // Check previous step
        if (iResult == ConstGlobal.RETURN_OK) {
            if (bReadHeaderResponse) {      // Read Header(s)
                iResult = readHeader(asUrl, objResponse);
                // Check previous step
                if (iResult != ConstGlobal.RETURN_OK) {
                    logger.severe("getRequestForUrlAsStream(): Error in method: readHeader()!"
                            + "\n\tUrl: " + asUrl
                            + "\n\tRedirectUrl: " + objResponse.sUrlRedirectLocation
                            + "\n\tRedirectCount: " + objResponse.iRedirectCount
                            + "\n\tReferer: " + sReferer
                            + "\n\tiResult: " + iResult);
                }
            }
        }

        // Check previous step
        if (objConn != null) {
            try {
                if ((objResponse.iResult < HTTP_RESP_CONTINUE) || (objResponse.iResult > (HttpURLConnection.HTTP_OK + 99)))
                    objResponse.objInputData = objConn.getErrorStream();
                else
                    objResponse.objInputData = objConn.getInputStream();
            } catch (IOException ex) {
                iResult = ConstGlobal.RETURN_ERROR;
                logger.severe("getRequestForUrlAsStream(): Error at getting HTTP Response (Msg.)!"
                        + " iResult: " + iResult
                        + "\n\tUrl: " + asUrl
                        + "; Msg.: " + ex.getMessage());
            }
        }
        return objResponse;
    }

    public ResultHttpStream getRequestForUrlAndGetResp(String asUrl) {
        // Local variables
        int              iResult;
        ResultHttpStream objResponse = null;

        // Initialization
        iResult = ConstGlobal.RETURN_OK;

        // Check previous step
        if (iResult == ConstGlobal.RETURN_OK) {
            objResponse = getRequestForUrlAsStream(asUrl);
            if (objResponse == null) {
                iResult = ConstGlobal.RETURN_ERROR;
                logger.severe("getRequestForUrlAndGetResp(): Error - No data! ResponseCode: UnKnown!!"
                        + "\n\tUrl: " + asUrl
                        + "\n\tReferer: " + sReferer
                        + "\n\tiResult: " + iResult);
            } else {
                if (objResponse.objInputData == null) {
                    iResult = ConstGlobal.RETURN_ERROR;
                    logger.fine("getRequestForUrlAndGetResp(): No data! ResponseCode: " + objResponse.iResult
                            + "\n\tUrl: " + asUrl
                            + "\n\tReferer: " + sReferer
                            + "\n\tiResult: " + iResult);
                }
            }
        }

        // Check previous step
        if ((objConn != null) && (objResponse.objInputData != null)) {
            iResult = readRequestData(objResponse);
            if (iResult != ConstGlobal.RETURN_OK) {
                logger.severe("getRequestForUrlAndGetResp(): Error in method: readRequestData()!"
                        + "\n\tUrl: " + asUrl
                        + "\n\tReferer: " + sReferer
                        + "\n\tiResult: " + iResult);
            }
        }

        closeConnection();
        {
            StringBuilder sMsgLog = new StringBuilder();
            sMsgLog.append("getRequestForUrlAndGetResp(): Stop. ResponseCode: " + objResponse.iResult
                    + "; Method: " + "GET"
                    + "; URL: " + asUrl
                    + "; iResult: " + iResult
                    + "; iCountRequest: " + iCountRequest
                    + "; ContentLength: " + objResponse.iContentLength
                    + "; DataRead: " + objResponse.iDataRead
                    + "; Header(s): " + objResponse.objHeaders);
            sMsgLog.append("\n\tResponse[");
            if (objResponse.sText != null)
                sMsgLog.append(objResponse.sText.length());
            sMsgLog.append("]: ");
            if (objResponse.sText != null) {
                if (objResponse.sText.length() > iLengthMaxResponseLog) {
                    sMsgLog.append(objResponse.sText.substring(0, iLengthMaxResponseLog));
                    sMsgLog.append(" ..");
                } else {
                    sMsgLog.append(objResponse.sText);
                }
            }
            if (GlobalVar.bIsModeVerbose) {
                if (iResult == ConstGlobal.RETURN_OK)
                    logger.info(sMsgLog.toString());
                else
                    logger.warning(sMsgLog.toString());
            } else {
                logger.fine(sMsgLog.toString());
            }
        }
        return objResponse;
    }
    public String getRequestForUrl(String asUrl) {
        // Local variables
        int              iResult;
        ResultHttpStream objResponse = null;

        // Initialization
        iResult = ConstGlobal.RETURN_OK;

        // Check previous step
        if (iResult == ConstGlobal.RETURN_OK) {
            objResponse = getRequestForUrlAndGetResp(asUrl);
            if (objResponse == null) {
                iResult = ConstGlobal.RETURN_ERROR;
                logger.severe("getRequestForUrl(): Error - No data! ResponseCode: UnKnown!!"
                        + "\n\tUrl: " + asUrl
                        + "\n\tReferer: " + sReferer
                        + "\n\tiResult: " + iResult);
            } else {
                if (objResponse.objInputData == null) {
                    iResult = ConstGlobal.RETURN_ERROR;
                    logger.fine("getRequestForUrl(): No data! ResponseCode: " + objResponse.iResult
                            + "\n\tUrl: " + asUrl
                            + "\n\tReferer: " + sReferer
                            + "\n\tiResult: " + iResult);
                }
            }
        }
        if (objResponse == null)
            return null;
        return objResponse.sText;
    }


    protected int readHeader(String asUrl, ResultHttpStream aobjResponse) {
        // Local variables
        int                 iResult;

        // Initialization
        iResult = ConstGlobal.RETURN_OK;

        // Read Header(s)
        //
        // Check previous step
        if (objConn != null) {
            StringBuilder       sTemp = new StringBuilder();
            Map<String, String> objHeaders = new HashMap<>();

            for (Map.Entry<String, List<String>> entries : objConn.getHeaderFields().entrySet()) {
                sTemp.delete(0, sTemp.length());
                for (String value : entries.getValue()) {
                    if (sTemp.length() > 0) sTemp.append(", ");
                    sTemp.append(value);
                }
                if (entries.getKey() == null)
                    objHeaders.put("Response", sTemp.toString());
                else {
                    String sTempKey = entries.getKey();
                    objHeaders.put(sTempKey, sTemp.toString());
                    if (sTempKey.toLowerCase().contentEquals("content-length")) {
                        try {
                            aobjResponse.iContentLength = Integer.parseInt(sTemp.toString());
                        } catch (Exception ex) {
                            logger.severe("postPutRequestForUrl(): Content-Length number parse error!!"
                                    + "; Value: " + sTempKey + " = " + sTemp
                                    + "; Url: " + asUrl
                                    + "; Msg.: " + ex.getMessage());
                        }
                    }
                    if (sTempKey.toLowerCase().contentEquals("content-type")) {
                        if (    (sTemp.toString().toLowerCase().startsWith("application/octet-stream")) ||
                                (sTemp.toString().toLowerCase().startsWith("application/pdf")) ||
                                (sTemp.toString().toLowerCase().startsWith("application/timestamp-reply")) )
                            aobjResponse.bIsBinary = true;
                    }
                }
            }
            if (!objHeaders.isEmpty()) {
                aobjResponse.objHeaders = objHeaders;
                //System.out.println("Response: " + objResponse.objHeaders);
            }
        }
        return iResult;
    }


    protected int readRequestData(ResultHttpStream aobjResponse) {
        // Local variables
        int                 iResult;
        InputStreamReader   objIn = null;

        // Initialization
        iResult = ConstGlobal.RETURN_OK;

        // Check previous step
        if (iResult == ConstGlobal.RETURN_OK) {
            if (aobjResponse == null) {
                iResult = ConstGlobal.RETURN_ERROR;
                logger.severe("readRequestData(): Error - No data! ResponseCode: UnKnown!!"
                        + "\n\tUrl: " + sURL
                        + "\n\tReferer: " + sReferer
                        + "\n\tiResult: " + iResult);
            } else {
                if (aobjResponse.objInputData == null) {
                    iResult = ConstGlobal.RETURN_ERROR;
                    logger.fine("readRequestData(): No data! ResponseCode: " + aobjResponse.iResult
                            + "\n\tUrl: " + sURL
                            + "\n\tReferer: " + sReferer
                            + "\n\tiResult: " + iResult);
                }
            }
        }

        // Check previous step
        if ((objConn != null) && (aobjResponse.objInputData != null)) {
            String              inputLine;
            StringBuffer        content = new StringBuffer();
            BufferedReader      objInBuffer = null;

            if (aobjResponse.bIsBinary) {
                int     iDataRead = 0;
                int     iDataDestPosition = 0;
                byte[]  arrData = new byte[aobjResponse.iContentLength + 16];
                byte[]  arrDataRead = new byte[1024 * 4];

                while (iDataRead > -1) {
                    try {
                        iDataRead = aobjResponse.objInputData.read(arrDataRead);
                        if (iDataRead != -1) {
                            if (iDataDestPosition + iDataRead > aobjResponse.iContentLength + 15) {
                                iResult = ConstGlobal.RETURN_TOOMUCHDATA;
                                logger.severe("readRequestData(): TooMuch HTTP data for Response (actual data / payload)!"
                                        + "\n\tUrl: " + sURL
                                        + "; iResult: " + iResult
                                        + "; Content-Length: " + aobjResponse.iContentLength
                                        + "; DataRecv: " + iDataDestPosition
                                        + "; DataRecvAddIn: " + iDataRead
                                        + "; Msg.: /");
                                break;
                            } else {
                                System.arraycopy(arrDataRead, 0, arrData, iDataDestPosition, iDataRead);
                                iDataDestPosition += iDataRead;
                            }
                        }
                    } catch (IOException ex) {
                        iResult = ConstGlobal.RETURN_ERROR;
                        logger.severe("readRequestData(): Error at getting HTTP Response (actual data / payload)!"
                                + "\n\tUrl: " + sURL
                                + "; iResult: " + iResult
                                + "; DataRecv: " + content.length()
                                + "; Msg.: " + ex.getMessage());
                        if (GlobalVar.bIsModeVerbose)
                            ex.printStackTrace();
                    }
                }
                try {
                    aobjResponse.objInputData.close();
                } catch (IOException ex) {
                    if (GlobalVar.bIsModeVerbose)
                        ex.printStackTrace();
                }
                aobjResponse.arrInputData = arrData;
                aobjResponse.iDataRead = iDataDestPosition;
                aobjResponse.sText = new String(aobjResponse.arrInputData);
            } else {
                try {
                    objIn = new InputStreamReader(aobjResponse.objInputData);
                    objInBuffer = new BufferedReader(objIn);
                    while ((inputLine = objInBuffer.readLine()) != null) {
                        content.append(inputLine);
                    }
                } catch (SocketTimeoutException ex) {
                    iResult = ConstGlobal.RETURN_ENDOFDATA;
                    logger.severe("readRequestData(): Error at getting HTTP Response (actual data / payload)!"
                            + "\n\tUrl: " + sURL
                            + "; iResult: " + iResult
                            + "; DataRecv: " + content.length()
                            + "; Msg.: TimeOut Exception! " + ex.getMessage());
                } catch (IOException ex) {
                    iResult = ConstGlobal.RETURN_ERROR;
                    logger.severe("readRequestData(): Error at getting HTTP Response (actual data / payload)!"
                            + "\n\tUrl: " + sURL
                            + "; iResult: " + iResult
                            + "; DataRecv: " + content.length()
                            + "; Msg.: " + ex.getMessage());
                    if (GlobalVar.bIsModeVerbose)
                        ex.printStackTrace();
                } finally {
                    try {
                        if (objInBuffer != null) objInBuffer.close();
                        if (objIn != null) objIn.close();
                        aobjResponse.objInputData.close();
                    } catch (IOException ex) {
                        if (GlobalVar.bIsModeVerbose)
                            ex.printStackTrace();
                    }
                    aobjResponse.sText = content.toString();
                    aobjResponse.iDataRead = content.length();
                }
            }
        }
        if ((iResult == ConstGlobal.RETURN_ENDOFDATA) || (iResult == ConstGlobal.RETURN_ERROR)) {
            if (GlobalVar.bIsModeVerbose) {
                logger.severe("readRequestData(): Data received until Error condition:"
                        + "\n\tUrl: " + sURL
                        + "; iResult: " + iResult
                        + "\n\tData: " + aobjResponse.sText);
            }
        }
        return iResult;
    }


    public String postRequestForUrl(String asUrl, String asParam) {
        ResultHttpStream objResponse;

        objResponse = postPutRequestForUrl(HTTP_METHOD_NAME_POST, asUrl, asParam, null);
        if (objResponse == null) return null;
        else return objResponse.sText;
    }
    public ResultHttpStream postRequestForUrlAndGetResp(String asUrl, String asParam) {
        ResultHttpStream objResponse;

        objResponse = postPutRequestForUrl(HTTP_METHOD_NAME_POST, asUrl, asParam, null);
        return objResponse;
    }
    public ResultHttpStream postRequestForUrlAndGetResp(String asUrl, byte[] aarrDataPayload) {
        ResultHttpStream objResponse;

        objResponse = postPutRequestForUrl(HTTP_METHOD_NAME_POST, asUrl, null, aarrDataPayload);
        return objResponse;
    }

    protected String putRequestForUrl(String asUrl, String asParam) {
        ResultHttpStream objResponse;

        objResponse = postPutRequestForUrl(HTTP_METHOD_NAME_PUT, asUrl, asParam, null);
        if (objResponse == null) return null;
        else return objResponse.sText;
    }
    public ResultHttpStream putRequestForUrlAndGetResp(String asUrl, String asParam) {
        ResultHttpStream objResponse;

        objResponse = postPutRequestForUrl(HTTP_METHOD_NAME_PUT, asUrl, asParam, null);
        return objResponse;
    }

    private ResultHttpStream postPutRequestForUrl(String asMethod, String asUrl, String asParam, byte[] aarrDataPayload) {
        // Local variables
        int             iResult;
        ResultHttpStream objResponse = new ResultHttpStream();

        // Initialization
        iResult = ConstGlobal.RETURN_OK;
        iCountRequest++;

        // Check previous step
        if (iResult == ConstGlobal.RETURN_OK) {
            iResult = openConnection(asMethod, asUrl, asParam, aarrDataPayload);
            // Error
            if (iResult != ConstGlobal.RETURN_OK) {
                objResponse.iResult = iResult;
                logger.severe("postPutRequestForUrl(): Error at connecting to service!"
                        + " URL: " + asUrl
                        + "; iResult: " + iResult);
            }
        }

        // Check previous step
        if (iResult == ConstGlobal.RETURN_OK) {
            try {
                objResponse.iResult = objConn.getResponseCode();
                logger.fine("postPutRequestForUrl(): Connection = Ok. ResponseCode: " + objResponse.iResult
                        + "; iResult: " + iResult);
            } catch (SSLHandshakeException ex) {
                iResult = ConstGlobal.RETURN_NOCONNECTION;
                objResponse.iResult = iResult;
                objResponse.sMsg.append(ex.getMessage());
                if (ex.getCause() != null)
                    objResponse.sMsg.append(" > ").append(ex.getCause().getMessage());
                logger.severe("postPutRequestForUrl(): Error at getting HTTP Response - SSLHandshakeException!"
                        + " URL: " + asUrl
                        + "; iResponseHttp: " + objResponse.iResult
                        + "; iResult: " + iResult
                        + "; Msg.: " + objResponse.sMsg.toString());
                if (GlobalVar.bIsModeVerbose)
                    ex.printStackTrace();
            } catch (IOException ex) {
                iResult = ConstGlobal.RETURN_NOCONNECTION;
                objResponse.iResult = iResult;
                objResponse.sMsg.append(ex.getMessage());
                if (ex.getCause() != null)
                    objResponse.sMsg.append(" > ").append(ex.getCause().getMessage());
                logger.severe("postPutRequestForUrl(): Error at getting HTTP Response!"
                        + " URL: " + asUrl
                        + "; iResponseHttp: " + objResponse.iResult
                        + "; iResult: " + iResult
                        + "; Msg.: " + objResponse.sMsg.toString());
                if (GlobalVar.bIsModeVerbose)
                    ex.printStackTrace();
            }
            if (objResponse.iResult != ConstWeb.HTTP_RESP_OK) {
                // NOT Cool ..
                iResult = objResponse.getResultCodeProcess();
                if (objResponse.sMsg.length() < 1)
                    objResponse.sMsg.append("ø");
                objResponse.sMsg.append(" : Response = NOT Ok. ResponseCode: " + objResponse.iResult);
                objResponse.sMsg.append("; iResult: " + iResult);
                logger.warning("postPutRequestForUrl(): " + objResponse.sMsg.toString());
            }
        }

        if (bReadHeaderResponse) {      // Read Header(s)
            iResult = readHeader(asUrl, objResponse);
            // Check previous step
            if (iResult != ConstGlobal.RETURN_OK) {
                logger.severe("postPutRequestForUrl(): Error in method: readHeader()!"
                        + "\n\tUrl: " + asUrl
                        + "\n\tRedirectUrl: " + objResponse.sUrlRedirectLocation
                        + "\n\tRedirectCount: " + objResponse.iRedirectCount
                        + "\n\tReferer: " + sReferer
                        + "\n\tiResult: " + iResult);
            }
        }

        // Check previous step
        if (objConn != null) {
            try {
                if ((objResponse.iResult < HTTP_RESP_CONTINUE) || (objResponse.iResult > (HttpURLConnection.HTTP_OK + 99)))
                    objResponse.objInputData = objConn.getErrorStream();
                else
                    objResponse.objInputData = objConn.getInputStream();
            } catch (IOException ex) {
                if (iResult == ConstGlobal.RETURN_OK)
                    iResult = ConstGlobal.RETURN_NODATA;
                else
                    objResponse.sMsg.append(" > ");
                objResponse.sMsg.append(ex.getMessage());
                if (ex.getCause() != null)
                    objResponse.sMsg.append(" > ").append(ex.getCause().getMessage());
                logger.severe("postPutRequestForUrl(): " + objResponse.sMsg.toString()
                        + "; Url: " + asUrl
                        + "; iResult: " + iResult);
            }
        }

        // Check previous step
        if ((objConn != null) && (objResponse.objInputData != null)) {
            iResult = readRequestData(objResponse);
            if (iResult != ConstGlobal.RETURN_OK) {
                logger.severe("postPutRequestForUrl(): Error in method: readRequestData()!"
                        + "\n\tUrl: " + asUrl
                        + "\n\tReferer: " + sReferer
                        + "\n\tiResult: " + iResult);
            }
        }

        closeConnection();

        {
            StringBuilder sMsgLog = new StringBuilder();
            sMsgLog.append("postPutRequestForUrl(): Stop. ResponseCode: " + objResponse.iResult
                    + "; Method: " + asMethod
                    + "; URL: " + asUrl
                    + "; iResult: " + iResult
                    + "; iCountRequest: " + iCountRequest
                    + "; ContentLength: " + objResponse.iContentLength
                    + "; DataRead: " + objResponse.iDataRead
                    + "; Header(s): " + objResponse.objHeaders);
            sMsgLog.append("\n\tResponse[");
            if (objResponse.sText != null)
                sMsgLog.append(objResponse.sText.length());
            sMsgLog.append("]: ");
            if (objResponse.sText != null) {
                if (objResponse.sText.length() > iLengthMaxResponseLog) {
                    sMsgLog.append(objResponse.sText.substring(0, iLengthMaxResponseLog));
                    sMsgLog.append(" ..");
                } else {
                    sMsgLog.append(objResponse.sText);
                }
            }
            if ((objResponse.sText != null) && (objResponse.sText.toLowerCase().contains("error"))) {
                logger.warning(sMsgLog.toString());
            } else {
                if (GlobalVar.bIsModeVerbose) {
                    logger.info(sMsgLog.toString());
                } else {
                    logger.fine(sMsgLog.toString());
                }
            }
        }
        return objResponse;
    }
}
