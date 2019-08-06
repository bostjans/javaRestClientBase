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
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.logging.Logger;


public class ClientHttpBase {

    protected boolean           bAddRefererParam = true;
    protected boolean           bAddOriginParam = false;
    protected boolean           bIsJsonRequest = true;
    protected boolean           bFunctionalityFollowRedirect = false;
    protected boolean           bFunctionalitySSLTrustAll = false;

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

    private URL                 objUrl = null;
    private HttpURLConnection   objConn = null;

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
        try {
            HttpsURLConnection.setDefaultHostnameVerifier(new HostnameVerifier(){
                public boolean verify(String hostname, SSLSession session) {
                    logger.info("trustEveryone(): verify(): Check for Host: " + hostname);
                    return true;
                }});
            SSLContext context = SSLContext.getInstance("SSL");
            //SSLContext context = SSLContext.getInstance("TLS");
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
            e.printStackTrace();
        }
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


    private int openConnection(String asUrl) {
        return openConnection("GET", asUrl, null);
    }

    private int openConnection(String asMethod, String asUrl, String asParam) {
        // Local variables
        int                 iResult;

        // Initialization
        iResult = ConstGlobal.RETURN_OK;

        try {
            objUrl = new URL(asUrl);
        } catch (Exception ex) {
            iResult = ConstGlobal.RETURN_ERROR;
            logger.severe("openConnection(): URL is wrong .."
                    + " URL: " + asUrl
                    + "; Msg.: " + ex.getMessage());
            ex.printStackTrace();
        }
        // Check previous step
        if (iResult == ConstGlobal.RETURN_OK) {
            try {
                objConn = (HttpURLConnection) objUrl.openConnection();
            } catch (Exception ex) {
                iResult = ConstGlobal.RETURN_ERROR;
                logger.severe("openConnection(): Error at opening connection!!"
                        + " URL: " + asUrl
                        + "; Msg.: " + ex.getMessage());
            }
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
            if (iTimeoutConnect == 0) iTimeoutConnect = iTimeoutConnectDefault;
            if (iTimeoutResponseRead == 0) iTimeoutResponseRead = iTimeoutResponseReadDefault;
            objConn.setConnectTimeout(iTimeoutConnect);
            objConn.setReadTimeout(iTimeoutResponseRead);
        }

        // Check previous step
        if (iResult == ConstGlobal.RETURN_OK) {
            iResult = updateConnectionParam(objConn);
            // Error
            if (iResult != ConstGlobal.RETURN_OK) {
                logger.severe("openConnection(): Error at updateConnectionParam(conn) for service!"
                        + " URL: " + asUrl
                        + "; iResult: " + iResult);
            }
        }
        // Check previous step
        if (iResult == ConstGlobal.RETURN_OK) {
            iResult = updateConnectionParam(objConn, asParam);
            // Error
            if (iResult != ConstGlobal.RETURN_OK) {
                logger.severe("openConnection(): Error at updateConnectionParam(conn, param) for service!"
                        + " URL: " + asUrl
                        + "; iResult: " + iResult);
            }
        }

        // Check previous step
        if (iResult == ConstGlobal.RETURN_OK) {
            try {
                objConn.connect();
            } catch (IOException ex) {
                iResult = ConstGlobal.RETURN_ERROR;
                logger.severe("openConnection(): Error at connecting to URL:Port!!"
                        + "\n\tURL: " + asUrl
                        + "\n\tPort: " + objUrl.getPort()
                        + ";\n\tMsg.: " + ex.getMessage());
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
        byte[]      arrParams = null;

        // Initialization
        iResult = ConstGlobal.RETURN_OK;
        //logger.info("updateConnectionParam(): Start ..  -  "
        //        + " sURL: " + sURL
        //        + "\n\tParam.: " + asParam);

        // Check previous step
        if (iResult == ConstGlobal.RETURN_OK) {
            if (asParam != null) {
                OutputStream        objOut = null;
                //DataOutputStream    objOut = null;
                //OutputStreamWriter  objOsw = null;

                try {
                    //arrParams = asParam.getBytes("UTF-8");
                    arrParams = asParam.getBytes(StandardCharsets.UTF_8);

                    //aobjConn.setRequestProperty("Referer", sReferer);
                    aobjConn.setRequestProperty("Content-Length", Integer.toString(arrParams.length));
                    aobjConn.setDoOutput(true);
                    objOut = new DataOutputStream(aobjConn.getOutputStream());

                    //objOut.writeBytes(ParameterStringBuilder.getParamsString(parameters));

                    //objOut = aobjConn.getOutputStream();
                    //objOsw = new OutputStreamWriter(objOut, ConstGlobal.ENCODING_UTF_8);
                    //objOsw.write(asParam);

                    objOut.write(arrParams);
                    objOut.flush();
                    //objOut.writeBytes(asParam);

                    //objOsw.flush();
                    //objOsw.close();
                    objOut.close();  //don't forget to close the OutputStream
                } catch (IOException ex) {
                    iResult = ConstGlobal.RETURN_ERROR;
                    logger.severe("updateConnectionParam(): Error at setting HTTP Parameters!"
                            + " sURL: " + sURL
                            + "; iResult: " + iResult);
                    ex.printStackTrace();
                }
            }
        }
        return iResult;
    }

    protected int updateConnectionParam(HttpURLConnection aobjConn) {
        // Local variables
        int             iResult;

        // Initialization
        iResult = ConstGlobal.RETURN_OK;

        // Check previous step
        if (iResult == ConstGlobal.RETURN_OK) {
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
            } catch (Exception ex) {
                iResult = ConstGlobal.RETURN_ERROR;
                logger.severe("updateConnectionParam(): Error at setting HTTP Parameters!"
                        + " sURL: " + sURL
                        + "; iResult: " + iResult
                        + "; Msg.: " + ex.getMessage());
                ex.printStackTrace();
            }
        }
        return iResult;
    }


    protected ResultHttpStream testRequestForUrl(String asUrl) {
        // Local variables
        int             iResult;
        ResultHttpStream objResponse = new ResultHttpStream();

        // Initialization
        iResult = ConstGlobal.RETURN_OK;

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
                logger.fine("getRequestForUrlAsStream(): Connection = Ok. ResponseCode: " + objResponse.iResult
                        + "; iResult: " + iResult);
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
        //if (iResult == Constant.i_func_return_OK)
        if (objConn != null) {
            try {
                objResponse.objInputData = objConn.getInputStream();
            } catch (IOException ex) {
                iResult = ConstGlobal.RETURN_ERROR;
                logger.severe("getRequestForUrlAsStream(): Error at getting HTTP Response (Msg.)!"
                        + " Url: " + asUrl
                        + "\n\tiResult: " + iResult
                        + "; Msg.: " + ex.getMessage());
                //} finally {
            }
        }
        return objResponse;
    }

    public String getRequestForUrl(String asUrl) {
        // Local variables
        int             iResult;
        ResultHttpStream objResponse = null;

        // Initialization
        iResult = ConstGlobal.RETURN_OK;
        //iCountRequest++;

        // Check previous step
        if (iResult == ConstGlobal.RETURN_OK) {
            objResponse = getRequestForUrlAsStream(asUrl);
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

        // Check previous step
        if ((objConn != null) && (objResponse.objInputData != null)) {
            iResult = readRequestData(objResponse);
            if (iResult != ConstGlobal.RETURN_OK) {
                logger.severe("getRequestForUrl(): Error in method: readRequestData()!"
                        + "\n\tUrl: " + asUrl
                        + "\n\tReferer: " + sReferer
                        + "\n\tiResult: " + iResult);
            }
        }

        closeConnection();

        {
            StringBuilder sMsgLog = new StringBuilder();
            sMsgLog.append("getRequestForUrl(): Stop. ResponseCode: " + objResponse.iResult
                    + "; iResult: " + iResult
                    + "; iCountRequest: " + iCountRequest
                    + "\n\tUrl: " + asUrl);
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
                logger.info(sMsgLog.toString());
            } else {
                logger.fine(sMsgLog.toString());
            }
        }
        return objResponse.sText;
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
            BufferedReader objInBuffer = null;

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
                        + "; Msg.: TimeOut Exception! " + ex.getMessage());
            } catch (IOException ex) {
                iResult = ConstGlobal.RETURN_ERROR;
                logger.severe("readRequestData(): Error at getting HTTP Response (actual data / payload)!"
                        + "\n\tUrl: " + sURL
                        + "; iResult: " + iResult
                        + "; Msg.: " + ex.getMessage());
                if (GlobalVar.bIsModeVerbose) {
                    ex.printStackTrace();
                }
            } finally {
                try {
                    if (objInBuffer != null) objInBuffer.close();
                    if (objIn != null) objIn.close();
                } catch (IOException ex) { }
                aobjResponse.sText = content.toString();
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
//        if (UtilString.isEmpty(aobjResponse.sText)) {
//            aobjResponse.sText = "{ \"responseHttp\": " + aobjResponse.iResult + " }";
//        }
        return iResult;
    }


    public String postRequestForUrl(String asUrl, String asParam) {
        ResultHttpStream objResponse;

        objResponse = postPutRequestForUrl("POST", asUrl, asParam);
        if (objResponse == null) return null;
        else return objResponse.sText;
    }
    public ResultHttpStream postRequestForUrlAndGetResp(String asUrl, String asParam) {
        ResultHttpStream objResponse;

        objResponse = postPutRequestForUrl("POST", asUrl, asParam);
        return objResponse;
    }

    protected String putRequestForUrl(String asUrl, String asParam) {
        ResultHttpStream objResponse;

        objResponse = postPutRequestForUrl("PUT", asUrl, asParam);
        if (objResponse == null) return null;
        else return objResponse.sText;
    }
    public ResultHttpStream putRequestForUrlAndGetResp(String asUrl, String asParam) {
        ResultHttpStream objResponse;

        objResponse = postPutRequestForUrl("PUT", asUrl, asParam);
        return objResponse;
    }

    private ResultHttpStream postPutRequestForUrl(String asMethod, String asUrl, String asParam) {
        // Local variables
        int             iResult;
        ResultHttpStream objResponse = new ResultHttpStream();

        // Initialization
        iResult = ConstGlobal.RETURN_OK;
        iCountRequest++;

        // Check previous step
        if (iResult == ConstGlobal.RETURN_OK) {
            iResult = openConnection(asMethod, asUrl, asParam);
            // Error
            if (iResult != ConstGlobal.RETURN_OK) {
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
            } catch (IOException ex) {
                iResult = ConstGlobal.RETURN_ERROR;
                logger.severe("postPutRequestForUrl(): Error at getting HTTP Response!"
                        + " URL: " + asUrl
                        + "; iResponseHttp: " + objResponse.iResult
                        + "; iResult: " + iResult);
            }
            if (objResponse.iResult != ConstWeb.HTTP_RESP_OK) {
                // NOT Cool ..
                iResult = ConstGlobal.RETURN_ERROR;
                logger.warning("postPutRequestForUrl(): Response = NOT Ok. ResponseCode: " + objResponse.iResult
                        + "; iResult: " + iResult);
            }
        }

        // Check previous step
        if (objConn != null) {
            try {
                objResponse.objInputData = objConn.getInputStream();
            } catch (IOException ex) {
                iResult = ConstGlobal.RETURN_ERROR;
                logger.severe("postPutRequestForUrl(): Error at getting HTTP Response (Msg.)!"
                        + " Url: " + asUrl
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
                    + "\n\tUrl: " + asUrl);
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
//        if (sResult.toLowerCase().contains("error")) {
//            logger.warning(sTemp);
//        } else {
//            if (GlobalVar.bIsModeVerbose) logger.info(sTemp);
//            else logger.fine(sTemp);
//        }
        return objResponse;
    }
}
