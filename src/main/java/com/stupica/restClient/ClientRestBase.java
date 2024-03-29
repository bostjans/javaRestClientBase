package com.stupica.restClient;


import com.stupica.ConstGlobal;
import com.stupica.core.UtilString;
import com.stupica.httpClient.ClientHttpBase;
import com.stupica.httpClient.ResultHttpStream;

import java.net.HttpURLConnection;


public class ClientRestBase extends ClientHttpBase {

    public ClientRestBase() {
        super();
    }


    protected void init() {
        super.init();
    }


    protected int updateConnectionParam(HttpURLConnection aobjConn) {
        // Local variables
        int             iResult;

        // Initialization
        iResult = super.updateConnectionParam(aobjConn);

        // Check previous step
        if (iResult == ConstGlobal.RETURN_OK) {
            aobjConn.setRequestProperty("Accept", "application/json");
        }
        return iResult;
    }


    protected int readRequestData(ResultHttpStream aobjResponse) {
        // Local variables
        int               iResult;

        // Initialization
        iResult = super.readRequestData(aobjResponse);

        if (iResult == ConstGlobal.RETURN_ENDOFDATA) {
            if (UtilString.isEmpty(aobjResponse.sText)) {
                aobjResponse.sText = "{ \"responseHttp\": " + aobjResponse.iResult + ","
                        + " \"response\": \"error\","
                        + " \"responseCode\": " + iResult + ","
                        + " \"dataCountRead\": " + aobjResponse.iDataRead + ","
                        + " \"msg\": \"Socket TimeOut\""
                        + " }";
            }
        } else {
            if (UtilString.isEmpty(aobjResponse.sText)) {
                aobjResponse.sText = "{ \"responseHttp\": " + aobjResponse.iResult
                        + ", \"responseCode\": " + iResult
                        + ", \"dataCountRead\": " + aobjResponse.iDataRead
                        + " }";
            }
        }
        return iResult;
    }
}
