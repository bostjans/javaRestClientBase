package com.stupica.httpClient;


import com.stupica.ResultProces;

import java.io.InputStream;


public class ResultHttpStream extends ResultProces {

    public boolean     bIsRedirect = false;
    public String      sUrlRedirectLocation = null;
    public String      sCookies = null;

    public InputStream objInputData = null;
}
