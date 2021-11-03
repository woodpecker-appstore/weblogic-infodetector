package infodetec;

import me.gv7.woodpecker.plugin.*;
import me.gv7.woodpecker.requests.RawResponse;
import me.gv7.woodpecker.requests.Requests;

import java.net.Socket;
import java.util.LinkedHashMap;
import java.util.Map;



public class WeblogicInfoDetectorPlugin implements InfoDetector {
    public static String weblogic_version;
    public static boolean isIIOPOpen = false;
    public static boolean isT3Open = false;
    public static String[] comURLs = new String[]{
            "/console/login/LoginForm.jsp",
            "/bea_wls_deployment_internal/DeploymentService",
            "/bea_wls_internal/",
            "/_async/AsyncResponseService",
            "/wls-wsat/CoordinatorPortType",
            "/wls-wsat/CoordinatorPortType11",
            "/wls-wsat/ParticipantPortType",
            "/wls-wsat/ParticipantPortType11",
            "/wls-wsat/RegistrationPortTypeRPC",
            "/wls-wsat/RegistrationPortTypeRPC11",
            "/wls-wsat/RegistrationRequesterPortType",
            "/wls-wsat/RegistrationRequesterPortType11"
    };

    public String getInfoDetectorTabCaption() {
        return "all info detection";
    }

    public IArgsUsageBinder getInfoDetectorCustomArgs() {
        return null;
    }

    public LinkedHashMap<String, String> doDetect(ITarget target, Map<String, Object> map, IResultOutput resultOutput) throws Throwable {
        String targetURL = target.getAddress();
        String host = target.getHost();
        int port = target.getPort();
        boolean isSSL = false;
        if(target.getProtocol().equalsIgnoreCase("https")){
            isSSL = true;
        }

        LinkedHashMap<String,String> infos = new LinkedHashMap<String, String>();
        // 探测版本
        weblogic_version = WeblogicInfoUtil.getWeblogicVersion(targetURL);
        if(weblogic_version != null){
            infos.put("version",weblogic_version);
            resultOutput.successPrintln("version: " + weblogic_version);
        }else{
            resultOutput.failPrintln("Get version fail!");
        }

        // 探测协议
        try {
            String t3HelloInfo = WeblogicInfoUtil.getT3HelloInfo(host,port,isSSL);
            if (t3HelloInfo.startsWith("HELO:") && t3HelloInfo.contains("AS:") && t3HelloInfo.contains("HL:")) {
                isT3Open = true;
                resultOutput.successPrintln("T3 is open");
                infos.put("t3","true");
            }else if((t3HelloInfo.contains("Connection rejected")
                    || t3HelloInfo.contains("filter blocked Socket"))
                    && t3HelloInfo.contains("weblogic.security.net.FilterException")
                    && t3HelloInfo.contains("Security:090220")){
                isT3Open = false;
                resultOutput.errorPrintln("T3 is open,but filter enable");
            }else{
                isT3Open = false;
                resultOutput.failPrintln("T3 is close");
            }

            if (WeblogicInfoUtil.checkIIOP(host,port,isSSL)) {
                isIIOPOpen = true;
                resultOutput.successPrintln("IIOP is open");
                infos.put("iiop","true");
            }else{
                resultOutput.failPrintln("IIOP is close");
            }
        }catch (Exception e){
            e.printStackTrace();
        }

        // 探测组件
        String rootURL = target.getRootAddress();
        if(rootURL.endsWith("/")){
            rootURL = rootURL.substring(0,rootURL.length()-1);
        }

        for(String wlsUrl:comURLs){
            String tUrl = rootURL + wlsUrl;
            try {
                RawResponse rawResp = Requests.get(tUrl).verify(false).send();
                if (rawResp == null) {
                    resultOutput.warningPrintln("url:%s response is null!");
                    continue;
                }

                if (rawResp.getStatusCode() == 200) {
                    resultOutput.successPrintln(String.format("%s status_code:200", tUrl));
                    infos.put(tUrl,"200");
                } else {
                    resultOutput.failPrintln(String.format("%s status_code:%d", tUrl, rawResp.getStatusCode()));
                }
            }catch (Throwable e){
                resultOutput.errorPrintln(String.format("request %s erro:%s",wlsUrl, AllInfoDetector.pluginHelper.getThrowableInfo(e)));
            }
        }
        return infos;
    }
}
