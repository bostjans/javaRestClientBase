package com.stupica.restClient;


import com.stupica.core.UtilString;
import com.stupica.httpClient.ClientHttpBase;
import com.stupica.httpClient.ResultHttpStream;


public class ClientRestBase extends ClientHttpBase {

    //private static Logger logger = Logger.getLogger(ClientRestBase.class.getName());


    public ClientRestBase() {
        super();
    }


    protected void init() {
        super.init();
    }


    protected int readRequestData(ResultHttpStream aobjResponse) {
        // Local variables
        int               iResult;

        // Initialization
        iResult = super.readRequestData(aobjResponse);

        if (UtilString.isEmpty(aobjResponse.sText)) {
            aobjResponse.sText = "{ \"responseHttp\": " + aobjResponse.iResult + " }";
        }
        return iResult;
    }
}