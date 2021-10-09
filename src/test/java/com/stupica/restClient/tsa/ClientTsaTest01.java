package com.stupica.restClient.tsa;


import com.stupica.ConstGlobal;
import com.stupica.httpClient.ClientHttpBase;

import java.net.HttpURLConnection;


public class ClientTsaTest01 extends ClientHttpBase {

    protected void init() {
        super.init();
        bAddRefererParam = false;
        //bFunctionalitySSLTrustAll = true;
    }


    protected int updateConnectionParam(HttpURLConnection aobjConn) {
        // Local variables
        int             iResult;

        // Initialization
        iResult = super.updateConnectionParam(aobjConn);

        // Check previous step
        if (iResult == ConstGlobal.RETURN_OK) {
            aobjConn.setRequestProperty("Content-Type", "application/timestamp-query");
        }
        return iResult;
    }
}
