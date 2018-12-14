/*
 * Copyright (C) 2013 DobinRutishauser@broken.ch
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
package model;

import burp.*;
import gui.session.SessionManager;
import gui.session.SessionUser;
import java.io.IOException;
import java.io.Serializable;
import java.net.URL;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.commons.lang3.StringEscapeUtils;
import util.BurpCallbacks;

/**
 *
 * @author unreal
 */
public class SentinelHttpRequest implements Serializable {

    public static final String CRLF = "\r\n";
    public static final String SEPARATOR = ":";
    private LinkedList<SentinelHttpParam> httpParams = new LinkedList<SentinelHttpParam>();
    private LinkedList<SentinelHttpParamVirt> httpParamsVirt = new LinkedList<SentinelHttpParamVirt>();
    
    private SentinelHttpParam changeParam;
    private SentinelHttpParam origParam;
    
    private byte[] request;
    
    transient private IRequestInfo requestInfo; // re-init upon deserializing in readObject()
    private SentinelHttpService httpService;

    public SentinelHttpRequest() {
        // Void Deserializing constructor
    }

    // Deserializing
    private void readObject(java.io.ObjectInputStream in) throws IOException, ClassNotFoundException {
        in.defaultReadObject();

        // As I dont want to re-implement IRequestInfo, make it transient
        // and redo requestInfo upon deserializing
        
        if (request != null) {
            requestInfo = BurpCallbacks.getInstance().getBurp().getHelpers().analyzeRequest(httpService, request);
        } else {
            System.out.println("Could not restore requestInfo upon deserializing!");
        }
    }
    
    public SentinelHttpRequest(IHttpRequestResponse httpMessage) {
        request = httpMessage.getRequest();
        this.httpService = new SentinelHttpService(httpMessage.getHttpService());
        
        init(httpMessage);
    }
    
    /* This is used if the input is specified other than by burp (which gives bytearrays)
     * Thats why we strangely convert string to bytes */
    public SentinelHttpRequest(String r, IHttpService httpService) {
        this.httpService = new SentinelHttpService(httpService);
        this.request = BurpCallbacks.getInstance().getBurp().getHelpers().stringToBytes(r);
        init();
    }
    
    public SentinelHttpRequest(byte[] request, IHttpService httpService) {
        this.httpService = new SentinelHttpService(httpService);
        this.request = request;
        init();
    }
    
    /* IHttpPequestResponse has httpService
     * therefor it is able to set URL correctly
     */
    private void init(IHttpRequestResponse httpMessage) {
        requestInfo = BurpCallbacks.getInstance().getBurp().getHelpers().analyzeRequest(httpMessage);
        if (requestInfo == null) {
            System.out.println("Requestinfo null!!!");
            return;
        }        
        
        init2();
    }

    /* request and httpServices are seperated
     * May use old existing httpService, assuming it matches current request
     */
    private void init() {
        requestInfo = BurpCallbacks.getInstance().getBurp().getHelpers().analyzeRequest(httpService, request);
        if (requestInfo == null) {
            BurpCallbacks.getInstance().print("Requestinfo null!!!");
            return;
        }
        
        init2();
    }
    
    /*
     * requestInfo has to be set before calling this function
     */
    private void init2() {
        httpParams.clear();
        LinkedList<SentinelHttpParam> httpParamsNew = new LinkedList<SentinelHttpParam>();
        
        // Add standard parameter
        if (requestInfo.getParameters() != null) {
            for(IParameter param: requestInfo.getParameters()) {
                httpParamsNew.add(new SentinelHttpParam(param,false));
            }
        } else {
            BurpCallbacks.getInstance().print("requestinfo null!");
        }

        extractHeaderParameters(httpParamsNew, request,BurpCallbacks.getInstance().getBurp().getHelpers());

        // Sort parameter
        for(SentinelHttpParam sortParam: httpParamsNew) {
            if (sortParam.getType() == SentinelHttpParam.PARAM_URL) {
                httpParams.add(sortParam);
            }
        }
        for(SentinelHttpParam sortParam: httpParamsNew) {
            if (sortParam.getType() == SentinelHttpParam.PARAM_BODY) {
                httpParams.add(sortParam);
            }
        }
        for(SentinelHttpParam sortParam: httpParamsNew) {
            if (sortParam.getType() != SentinelHttpParam.PARAM_URL
                    && sortParam.getType() != SentinelHttpParam.PARAM_BODY ) {
                httpParams.add(sortParam);
            }
        }
        
        // add additional parameter
        initMyParams();
    }

    public static void extractHeaderParameters(LinkedList<SentinelHttpParam> httpParamsNew, byte[] request, IExtensionHelpers helpers) {
        int headersEnd = helpers.indexOf(request,(CRLF+CRLF).getBytes(),false,0,request.length);
        if(headersEnd==-1) {
            headersEnd = request.length;
        }
        for(int pos = 0; pos < headersEnd; ) {
            int newLine = helpers.indexOf(request, CRLF.getBytes(), false, pos, request.length);
            if(newLine == -1 ) {
                break;
            }
            String header = new String(request, pos, newLine - pos);

            if(header.contains("HTTP/") || header.startsWith("Content-Length")) {
                pos += header.length() + CRLF.length();
                continue;
            }

            int separatorIndex = header.indexOf(SEPARATOR);
            if(separatorIndex == -1 ) {
                BurpCallbacks.getInstance().print("Header line without separator, [" + header + "]");
                pos += header.length() + CRLF.length();
                continue;
            }

            String headerName = header.substring(0,separatorIndex);

            int headerStart = helpers.indexOf(request, headerName.getBytes(), false, pos, request.length);
            if(headerStart == -1) {
                BurpCallbacks.getInstance().print("Header not found: [" + header + "]");
                continue;
            }
            int headerEnd = headerStart + headerName.length();
            if(separatorIndex + pos < headerEnd) {
                BurpCallbacks.getInstance().print("Something wrong with header [" + header + "], separator not within a header line");
                continue;
            }
            int valueStart = separatorIndex;
            if (valueStart == -1 ) {
                BurpCallbacks.getInstance().print("Value not found for header:[" + header + "]");
                continue;
            }
            valueStart += SEPARATOR.length() + pos;
            // skip whitespace
            for(; valueStart < request.length && (request[valueStart] == 0x20 || request[valueStart] == 0x09);
                valueStart++ );

            int valueEnd = helpers.indexOf(request, CRLF.getBytes(),false,valueStart, request.length);
            String headerValue = new String(request,valueStart,valueEnd - valueStart);
            httpParamsNew.add(new SentinelHttpParam(SentinelHttpParam.PARAM_HEADER, headerName, headerStart, headerEnd,
                    headerValue,valueStart, valueEnd, false));
            pos = valueEnd + CRLF.length();
        }
    }

    private void initMyParams() {
        int newlineIndex = BurpCallbacks.getInstance().getBurp().getHelpers().indexOf(request, "\r\n".getBytes(), false, 0, request.length);
        if (newlineIndex < 0) {
            BurpCallbacks.getInstance().print("Error in HTTP Request: no newline");
            return;
        }
        
        String firstLine = new String ( Arrays.copyOfRange(request, 0, newlineIndex) );
        String header[] = firstLine.split(" ");
        if (header.length != 3) {
            return;
        }
        
        // Check if we have arguments
        int endPath = header[1].indexOf("?");
        if (endPath == -1) {
            endPath = header[1].length();
        }
        String myHeader = header[1].substring(0, endPath);

        // Extract path
        String path = "";
        if (myHeader.startsWith("/")) {
            path = myHeader;
        } else {
            int n = myHeader.indexOf('/', 9);
            path = myHeader.substring(n, myHeader.length());
        }
        
        // Split path
        LinkedList<SentinelHttpParam> pathParams = new LinkedList<SentinelHttpParam>();
        String[] p = path.split("/");
        int i = 0;
        int valEnd = firstLine.indexOf("/"); // index of first /
        for (String pathPart : p) {
            if (pathPart.length() == 0) {
                continue;
            }
            
            int valStart = valEnd;
            valStart++; // because of /
            valEnd = valStart + pathPart.length();

            SentinelHttpParam sentParam = new SentinelHttpParam(
                    SentinelHttpParam.PARAM_PATH,
                    Integer.toString(i), 0, 0, 
                    pathPart, valStart, valEnd, false);
            //httpParams.add(sentParam);
            pathParams.push(sentParam);
            i++;
        }
        httpParams.addAll(pathParams);

    }
    
    
    public URL getUrl() {
        return requestInfo.getUrl();
    }
    
    public String getMethod() {
        return requestInfo.getMethod();
    }
    
    
    /**
     * ************************** Getters*************************************
     * 
     * Note: the following functions are slow, as it extracts on the fly
     * Currently only used for clipboard helper
     */
    public String extractFirstLine() {
        String http = getRequestStr().substring(0, getRequestStr().indexOf("\r\n"));
        return http;
    }

    public List<String> extractHeaders() {
        return requestInfo.getHeaders();
    }

    public String extractBody() {
        String req = getRequestStr();

        String body = getRequestStr().substring(requestInfo.getBodyOffset());

        if (body.length() > 0) {
            return body;
        } else {
            return "";
        }
    }

    
    /**
     * ************************** Param **************************************
     */
    public void setChangeParam(SentinelHttpParam changeParam) {
        this.changeParam = changeParam;
        // TODO: Set orig param
    }
    
    
    // Write request
    public boolean applyChangeParam() {
        if (request == null || request.length == 0) {
            BurpCallbacks.getInstance().print("ApplyChangeParam: Cant apply changeparam - no request");
            return false;
        }
        if (origParam == null) {
            BurpCallbacks.getInstance().print("ApplyChangeParam: no orig param");
            return false;
        }

        byte paramType = changeParam.getType();
        switch(paramType) {
            case SentinelHttpParam.PARAM_PATH:
                request = updateParameterPath(request, changeParam);
                break;
            case SentinelHttpParam.PARAM_JSON:
                request = updateParameterJSON(request, changeParam);
                break;
            case SentinelHttpParam.PARAM_BODY:
            case SentinelHttpParam.PARAM_URL:    
            case SentinelHttpParam.PARAM_COOKIE:
                request = BurpCallbacks.getInstance().getBurp().getHelpers().updateParameter(request, changeParam);
                break;
            case SentinelHttpParam.PARAM_HEADER:
                request = updateHeader(request, changeParam);
                break;
            default:
                //BurpCallbacks.getInstance().print("ApplyChangeParam: Not supported type");    
                request = updateParameterJSON(request, changeParam); // We just try this for now...
                return true;
        }
        
        // Update httpparams linked with this request with correct offsets
        requestInfo = BurpCallbacks.getInstance().getBurp().getHelpers().analyzeRequest(httpService, request);
        for(IParameter newParam: requestInfo.getParameters()) {
            if (changeParam.isThisParameter(newParam)) {
                changeParam.updateLocationWith(newParam);
            }
        }
        
        // Update change param to reflect new state
        init();
        
        return true;
    }

    private byte[] updateHeader(byte[] request, SentinelHttpParam changeParam) {
        IExtensionHelpers helpers = BurpCallbacks.getInstance().getBurp().getHelpers();
        String req = helpers.bytesToString(request);
        StringBuilder r = new StringBuilder(req);
        r.replace(origParam.getValueStart(), origParam.getValueEnd(), changeParam.getValue());
        // rebuild request and recalculate Content-Length
        IRequestInfo newRequestInfo = helpers.analyzeRequest(helpers.stringToBytes(r.toString()));
        String newBody = r.substring(newRequestInfo.getBodyOffset());
        byte[] newRequest = helpers.buildHttpMessage(newRequestInfo.getHeaders(), helpers.stringToBytes(newBody) );
        return newRequest;
    }

    private byte[] updateParameterPath(byte[] request, SentinelHttpParam changeParam) {
        String req = BurpCallbacks.getInstance().getBurp().getHelpers().bytesToString(request);

        req = req.substring(0,origParam.getValueStart()) + changeParam.getValue() + req.substring(origParam.getValueEnd());

        return BurpCallbacks.getInstance().getBurp().getHelpers().stringToBytes(req);
    }
    
    private byte[] updateParameterJSON(byte[] request, SentinelHttpParam changeParam) {
        IExtensionHelpers helpers = BurpCallbacks.getInstance().getBurp().getHelpers();
        String req = helpers.bytesToString(request);
        StringBuilder r = new StringBuilder(req);
        if(changeParam.isRemove()){
            // is it a string (has " in it?)
            int fix = 0;
            if(origParam.valueStart > 0 && (int) r.charAt(origParam.valueStart-1) == '\"')
                fix = 1;
            r.replace(origParam.getValueStart() - fix, origParam.getValueEnd()+fix, changeParam.getValue());
        } else { // replace
            String encoded = StringEscapeUtils.escapeJava(changeParam.getValue());
            r.replace(origParam.getValueStart(), origParam.getValueEnd(), encoded);
        }
        // rebuild request and recalculate Content-Length
        IRequestInfo newRequestInfo = helpers.analyzeRequest(helpers.stringToBytes(r.toString()));
        String newBody = r.substring(newRequestInfo.getBodyOffset());
        byte[] newRequest = helpers.buildHttpMessage(newRequestInfo.getHeaders(), helpers.stringToBytes(newBody) );
        return newRequest;
    }
    

    public SentinelHttpParam getOrigParam() {
        return origParam;
    }

    public void setOrigParam(SentinelHttpParam origParam) {
        this.origParam = origParam;
    }

    public SentinelHttpParam getChangeParam() {
        return changeParam;
    }
    
    public String getRequestStr() {
        return BurpCallbacks.getInstance().getBurp().getHelpers().bytesToString(request);
    }
    
    public byte[] getRequestByte() {
        return request;
    }

    public Iterable<SentinelHttpParam> getParams() {
        return httpParams;
    }

    public SentinelHttpParam getParam(String name, byte type) {
        for(SentinelHttpParam param: httpParams) {
            if (param.getType() == type && param.getName().equals(name)) {
                return param;
            }
        }

        return null;
    }
    
    public void addParamVirt(SentinelHttpParamVirt paramVirt) {
        httpParamsVirt.add(paramVirt);
    }
    
    public Iterable<SentinelHttpParamVirt> getParamsVirt() {
        return httpParamsVirt;
    }
    

    /**
     * ************************** Session ************************************
     */
    public void changeSession(String sessionVarName, String sessionVarValue) {
        SentinelHttpParam updateParam = null;

        SentinelHttpParam param = getParam(sessionVarName, SentinelHttpParam.PARAM_COOKIE);
        if (param == null) {
            BurpCallbacks.getInstance().print("HttpRequest: ChangeSession(): Could not identify session var!");
            return;
        }
        
        // Dont update if they are already equal
        if (param.getValue().equals(sessionVarValue)) {
            return;
        }

        updateParam = new SentinelHttpParam(param, false);
        updateParam.changeValue(sessionVarValue);

        request = BurpCallbacks.getInstance().getBurp().getHelpers().updateParameter(request, updateParam);
        init();
    }
    
    public String getSessionValue() {
        String sessionName = SessionManager.getInstance().getSessionVarName();
        
        SentinelHttpParam sessionParam = getParam(sessionName, SentinelHttpParam.PARAM_COOKIE);
        if (sessionParam != null) {
            return sessionParam.getValue();
        } else{
            return null;
        }
    }
    
    public String getSessionValueTranslated() {
        String s = getSessionValue();
        if (s == null) {
            return "-";
        }
        
        SessionUser u = SessionManager.getInstance().getUserFor(s);
        if (u == null) {
            return s;
        } else {
            return u.getName();
        }
        
    }

    
}