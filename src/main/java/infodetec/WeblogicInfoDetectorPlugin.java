package infodetec;

import me.gv7.woodpecker.plugin.*;
import me.gv7.woodpecker.requests.RawResponse;
import me.gv7.woodpecker.requests.Requests;

import java.util.LinkedHashMap;
import java.util.Map;

import static infodetec.WeblogicInfoUtil.isT3FilterEnable;

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
        LinkedHashMap<String,String> infos = new LinkedHashMap<String, String>();

        String targetURL = target.getAddress();
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
            if (WeblogicInfoUtil.checkT3(targetURL)) {
                isT3Open = true;
                if(isT3FilterEnable(targetURL)){
                    resultOutput.errorPrintln("T3 is open,but filter enable");
                }else{
                    resultOutput.successPrintln("T3 is open,and filter disable");
                    infos.put("t3","true");
                }
            }else{
                resultOutput.failPrintln("T3 is close");
            }
            if (WeblogicInfoUtil.checkIIOP(targetURL)) {
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
