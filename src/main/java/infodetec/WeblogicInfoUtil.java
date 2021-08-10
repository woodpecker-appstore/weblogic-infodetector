package infodetec;

import javax.naming.Context;
import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.net.*;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class WeblogicInfoUtil {
    private static final Integer SOCKET_TIME_OUT = Integer.valueOf(15000);
    public static String VERSION_T3 = "74332031322e322e310a41533a3235350a484c3a31390a4d533a31303030303030300a50553a74333a2f2f75732d6c2d627265656e733a373030310a0a";

    public static String getWeblogicVersion(String url){
        String version = null;
        try {
            version = getVersionByHttp(url);
            if (version == null) {
                version = getVersionByT3(url);
            }
        }catch (Throwable t){
            t.printStackTrace();
        }
        return version;
    }


    public static String getVersionByHttp(String url) {
        String version = null;
        String result = "";
        url = url + "/console/login/LoginForm.jsp";
        try {
            URL realUrl = new URL(url);
            URLConnection connection = realUrl.openConnection();
            connection.setRequestProperty("accept", "*/*");
            connection.setRequestProperty("connection", "Keep-Alive");
            connection.setRequestProperty("user-agent", "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1;SV1)");
            connection.connect();
            BufferedReader in = new BufferedReader(new InputStreamReader(connection.getInputStream()));
            String line;
            while ((line = in.readLine()) != null) {
                result += line;
            }

            String pattern = "<p id=\"footerVersion\">.*?:(.*?)</p>";
            Pattern r = Pattern.compile(pattern);
            Matcher m = r.matcher(result);
            if(m.find()){
                version = m.group(1).trim();
            }
        } catch (Throwable e) {
            e.printStackTrace();
        }
        return version;
    }


    public static String getVersionByT3(String url) {
        try {
            URL targetURL = new URL(url);
            String ip = targetURL.getHost();
            Integer port = targetURL.getPort();
            if(port == -1){
                if(url.contains("https")){
                    port = 443;
                }else{
                    port = 80;
                }
            }
            return getVersionByT3(ip,port);
        }catch (Exception e){
            e.printStackTrace();
        }
        return null;
    }

    public static String getVersionByT3(String ip, Integer port) {
        String version = null;
        try {
            Socket socket = new Socket(ip, port.intValue());
            byte[] rspByte = send(VERSION_T3, socket);
            socket.close();
            String rspStr = new String(rspByte);
            String pattern = "HELO:(.*?)\\.false";
            Pattern r = Pattern.compile(pattern);
            Matcher m = r.matcher(rspStr);
            if (m.find()) {
                version = m.group(1);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return version;
    }

    public static Map<String, Object> getWeblogicNATInfo(Context context){
        Map<String, Object> natInfo = new HashMap<String, Object>();
        try {
            Field _defaultInitCtx = context.getClass().getDeclaredField("defaultInitCtx");
            _defaultInitCtx.setAccessible(true);
            Object defaultInitCtx = _defaultInitCtx.get(context);
            Field _ctx = defaultInitCtx.getClass().getDeclaredField("ctx");
            _ctx.setAccessible(true);
            Object ctx = _ctx.get(defaultInitCtx);
            Field __delegate = ctx.getClass().getSuperclass().getDeclaredField("__delegate");
            __delegate.setAccessible(true);
            Object delegate = __delegate.get(ctx);
            Field _ior = delegate.getClass().getSuperclass().getDeclaredField("ior");
            _ior.setAccessible(true);
            Object ior = _ior.get(delegate);
            Field _iopProfile = ior.getClass().getDeclaredField("iopProfile");
            _iopProfile.setAccessible(true);
            Object iopProfile = _iopProfile.get(ior);
            Field _host = iopProfile.getClass().getDeclaredField("host");
            _host.setAccessible(true);
            String host = (String)_host.get(iopProfile);

            Field _port = iopProfile.getClass().getDeclaredField("port");
            _port.setAccessible(true);
            Integer port = (Integer) _port.get(iopProfile);

            natInfo.put("host",host);
            natInfo.put("port",port);
        }catch (Exception e){
            e.printStackTrace();
        }
        return natInfo;
    }

    public static boolean setWeblogicNATInfo(Context context,String host,Integer port){
        Map<String, Object> natInfo = new HashMap<String, Object>();
        try {
            Field _defaultInitCtx = context.getClass().getDeclaredField("defaultInitCtx");
            _defaultInitCtx.setAccessible(true);
            Object defaultInitCtx = _defaultInitCtx.get(context);
            Field _ctx = defaultInitCtx.getClass().getDeclaredField("ctx");
            _ctx.setAccessible(true);
            Object ctx = _ctx.get(defaultInitCtx);
            Field __delegate = ctx.getClass().getSuperclass().getDeclaredField("__delegate");
            __delegate.setAccessible(true);
            Object delegate = __delegate.get(ctx);
            Field _ior = delegate.getClass().getSuperclass().getDeclaredField("ior");
            _ior.setAccessible(true);
            Object ior = _ior.get(delegate);
            Field _iopProfile = ior.getClass().getDeclaredField("iopProfile");
            _iopProfile.setAccessible(true);
            Object iopProfile = _iopProfile.get(ior);
            Field _host = iopProfile.getClass().getDeclaredField("host");
            _host.setAccessible(true);
            _host.set(iopProfile,host);

            Field _port = iopProfile.getClass().getDeclaredField("port");
            _port.setAccessible(true);
            _port.set(iopProfile,port);


            Method _getHostAddress =  iopProfile.getClass().getDeclaredMethod("getHostAddress");
            _getHostAddress.setAccessible(true);
            _getHostAddress.invoke(iopProfile,null);

            Method _getConnectionKey =  iopProfile.getClass().getDeclaredMethod("getConnectionKey");
            _getConnectionKey.setAccessible(true);
            _getConnectionKey.invoke(iopProfile,null);

            return true;
        }catch (Exception e){
            e.printStackTrace();
            return false;
        }
    }



    public static Socket getSocket(String target) throws Exception {
        URL url = new URL(target);
        int port = 0;

        if(url.getPort() != -1){
            port = url.getPort();
        }else if(target.startsWith("https://")){
            port = 443;
        }else if(target.startsWith("http://")){
            port = 80;
        }else{
            throw new Exception("unkown port");
        }

        String host = url.getHost();
        SocketAddress socketAddress = new InetSocketAddress(host, port);
        Socket socket = new Socket();
        socket.connect(socketAddress, SOCKET_TIME_OUT.intValue());
        socket.setSoTimeout(SOCKET_TIME_OUT.intValue());
        return socket;
    }

    public static boolean checkIIOP(String target) throws Exception{
        Socket socket = getSocket(target);
        try {
            byte[] rspByte = send("47494f50010200030000001700000002000000000000000b4e616d6553657276696365", socket);;
            String rsp = new String(rspByte);
            if (!rsp.contains("NamingContextAny") && !rsp.contains("weblogic") && !rsp.contains("corba")) {
                return false;
            }
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        } finally {
            socket.close();
        }

        return true;
    }




    public static boolean checkT3(String target) throws Exception {
        Socket socket = getSocket(target);
        try {
            byte[] rspByte = send(VERSION_T3, socket);
            String rsp = new String(rspByte);
            if (rsp.contains("<title>") || rsp.contains("<html>") || rsp.contains("400") || rsp.contains("403")) {
                return false;
            }
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        } finally {
            socket.close();
        }
        return true;
    }

    public static boolean isT3FilterEnable(String target) throws Exception {
        Socket socket = getSocket(target);
        try {
            byte[] rspByte = send(VERSION_T3, socket);
            String rsp = new String(rspByte);

            if((rsp.contains("Connection rejected") || rsp.contains("filter blocked Socket")) && rsp.contains("weblogic.security.net.FilterException") && rsp.contains("Security:090220")){
                return true;
            }
        } catch (Exception e) {
            return false;
        } finally {
            socket.close();
        }
        return false;
    }

    public static byte[] send(String msg, Socket socket) throws Exception {
        OutputStream out = socket.getOutputStream();
        InputStream is = socket.getInputStream();
        out.write(hexStrToBinaryStr(msg));
        out.flush();
        byte[] bytes = new byte[4096];
        int length = is.read(bytes);
        return Arrays.copyOfRange(bytes, 0, length);
    }

    public static byte[] hexStrToBinaryStr(String hexString) {
        hexString = hexString.replaceAll(" ", "");
        int len = hexString.length();
        int index = 0;
        byte[] bytes = new byte[len / 2];
        while (index < len) {
            String sub = hexString.substring(index, index + 2);
            bytes[index / 2] = (byte)Integer.parseInt(sub, 16);
            index += 2;
        }
        return bytes;
    }

}
