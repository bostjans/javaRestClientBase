package com.stupica.httpClient;


import com.stupica.ResultProces;

import java.io.InputStream;
import java.util.Map;

import static com.stupica.ConstGlobal.*;
import static com.stupica.ConstWeb.*;


public class ResultHttpStream extends ResultProces {

    public boolean     bIsRedirect = false;
    public boolean     bIsBinary = false;
    public int         iRedirectCount = 0;
    public String      sUrlRedirectLocation = null;
    public String      sCookies = null;

    public int          iContentLength = -1;
    public int          iDataRead = 0;
    public InputStream  objInputData = null;
    public byte[]       arrInputData = null;

    public Map<String, String> objHeaders = null;


    public int getResultCodeProcess() {
        int iReturnVal;

        switch (iResult) {
            case HTTP_RESP_SUCCESS: iReturnVal = RETURN_SUCCESS; break;
            case HTTP_RESP_NO_CREATED: iReturnVal = RETURN_WARNING; break;
            case HTTP_RESP_NO_CONTENT: iReturnVal = RETURN_NODATA; break;

            case HTTP_RESP_BAD_REQUEST: iReturnVal = RETURN_INVALID; break;
            case HTTP_RESP_UNAUTHORIZED: iReturnVal = RETURN_SEC_ERROR; break;
            case HTTP_RESP_FORBIDDEN: iReturnVal = RETURN_SEC_ERROR; break;
            case HTTP_RESP_NOT_FOUND: iReturnVal = RETURN_NODATA; break;
            case HTTP_RESP_MethodNotAllowed: iReturnVal = RETURN_SEC_ERROR; break;
            case HTTP_RESP_NotAcceptable: iReturnVal = RETURN_SEC_ERROR; break;
            case HTTP_RESP_ProxAuthRequired: iReturnVal = RETURN_SEC_ERROR; break;
            case HTTP_RESP_RequestTimeout: iReturnVal = RETURN_ENDOFDATA; break;
            case HTTP_RESP_Conflict: iReturnVal = RETURN_INVALID; break;
            case HTTP_RESP_PreconditionFailed: iReturnVal = RETURN_INVALID; break;
            case HTTP_RESP_ExpectationFailed: iReturnVal = RETURN_INVALID; break;

            case HTTP_RESP_INTERNAL_SRV_ERR: iReturnVal = RETURN_ERROR; break;
            case HTTP_RESP_NET_CONNECT_TIMEOUT: iReturnVal = RETURN_NOCONNECTION; break;

            default: iReturnVal = RETURN_UNKNOWN;
        }
        return iReturnVal;
    }
}
