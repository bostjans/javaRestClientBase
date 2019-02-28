package com.stupica.httpClient;


import com.stupica.ResultProces;

import java.io.InputStream;


public class ResultHttpStream extends ResultProces {

    public boolean     bIsRedirect = false;
    public int         iRedirectCount = 0;
    public String      sUrlRedirectLocation = null;
    public String      sCookies = null;

    public InputStream objInputData = null;
}
