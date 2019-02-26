package com.stupica.restClient;


import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.logging.Logger;


public class ServiceBase {

    protected final int   iMaxClients = 4;

    protected long        iCountRequest = 0L;

    protected String        sURL = "http://localhost:8080/lenko";
    protected String        sReferer = "http://localhost:3000";

    protected Map<Integer, Boolean> arrClientUsed;

    private static Logger logger = Logger.getLogger(ServiceBase.class.getName());


    protected void init() {
        arrClientUsed = new ConcurrentHashMap<Integer, Boolean>();
    }


    public void setUrl(String asVal) {
        sURL = asVal;
    }
    public void setsReferer(String asVal) {
        sReferer = asVal;
    }


    protected void putClientBack() {
        // Local variables
        int         iCount = 0;
        boolean     bIsBackFound = false;

        for (; iCount < iMaxClients; iCount++) {
            if (arrClientUsed.get(Integer.valueOf(iCount))) {
                arrClientUsed.put(Integer.valueOf(iCount), false);
                bIsBackFound = true;
                break;
            }
        }
        if (!bIsBackFound) {
            logger.severe("putClientBack(): Error: NO Used Client can be found!!"
                    + "; Contact support ..");
        }
    }
}
