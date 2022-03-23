package infodetec;

import net.dongliu.commons.Hexes;
import sun.misc.BASE64Encoder;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import java.io.*;
import java.net.*;
import java.util.HashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class WeblogicInfoUtil {
    private static final Integer SOCKET_TIME_OUT = Integer.valueOf(15000);

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
            boolean isSSL = false;
            URL targetURL = new URL(url);
            String ip = targetURL.getHost();
            Integer port = targetURL.getPort();
            if(port == -1){
                if(url.contains("https")){
                    port = 443;
                    isSSL = true;
                }else{
                    port = 80;
                }
            }
            return getVersionByT3(ip,port,isSSL);
        }catch (Exception e){
            e.printStackTrace();
        }
        return null;
    }

    public static String getVersionByT3(String ip, int port,boolean isSSL) throws Exception {
        String version = null;
        String rspStr = getT3HelloInfo(ip,port,isSSL);
        String pattern = "HELO:(.*?)\\.false";
        Pattern r = Pattern.compile(pattern);
        Matcher m = r.matcher(rspStr);
        if (m.find()) {
            version = m.group(1);
        }
        return version;
    }

    public static Socket initSocket(String host,int port,boolean isSSL) throws Exception {
        InetSocketAddress socketAddress = new InetSocketAddress(host, port);
        Socket socket = new Socket();;

        if (isSSL) {
            X509TrustManagerImpl x509m = new X509TrustManagerImpl();
            // 获取一个SSLContext实例
            SSLContext sslContext = SSLContext.getInstance("SSL");
            // 初始化SSLContext实例
            sslContext.init(null, new TrustManager[]{x509m}, new java.security.SecureRandom());
            socket.connect(socketAddress);
            socket.setSoTimeout(SOCKET_TIME_OUT.intValue());
            socket.setKeepAlive(true);
            socket = sslContext.getSocketFactory().createSocket(socket, socketAddress.getHostName(), socketAddress.getPort(), true);
        }else{
            socket.connect(socketAddress, SOCKET_TIME_OUT.intValue());
            socket.setSoTimeout(SOCKET_TIME_OUT.intValue());
            socket.setKeepAlive(true);
        }

        return socket;
    }

    public static String getIIOPHelloInfo(String host,int port,boolean isSSL) throws Exception {
        String hello = null;
        Socket socket = initSocket(host,port,isSSL);
        try {
            byte[] rspByte = send(hexStrToBinaryStr("47494f50010200030000001700000002000000000000000b4e616d6553657276696365"), socket);
            hello = new String(rspByte);
        } catch (Throwable t) {
            t.printStackTrace();
        } finally {
            socket.close();
        }
        return hello;
    }

    public static String getT3HelloInfo(String host,int port,boolean isSSL) throws Exception {
        String hello = null;
        Socket socket = initSocket(host,port,isSSL);
        try {
            String str = "t3 10.3.1\nAS:255\nHL:19\n\n";
            byte[] t3Response = WeblogicInfoUtil.send(str.getBytes(), socket);
            hello = new String(t3Response);
        } catch (Throwable t){
            t.printStackTrace();
        }finally {
            socket.close();
        }
        return hello;
    }


    public static byte[] send(byte[] msg, Socket socket) throws Exception {
        byte[] readedContent = null;
        OutputStream out = socket.getOutputStream();
        InputStream is = socket.getInputStream();
        out.write(msg);
        out.flush();
        byte[] buffer = new byte[1];

        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        boolean proccessedHeader = false;
        boolean isChunked = false;
        int contentLength = 0;
        int acceptedLength = 0;
        while (true){
            try {
                int flag = is.read(buffer);
                outputStream.write(buffer);
                outputStream.flush();
                readedContent = outputStream.toByteArray();
                String res = new String(readedContent);

                // t3协议
                if (res.startsWith("HELO:") && res.contains("AS:") && res.contains("HL:")) {
                    if (res.endsWith("\n\n")) {
                        break;
                    }
                }

                // http协议
                if (res.startsWith("HTTP/")) {
                    // 读取http协议header
                    if(!proccessedHeader && res.endsWith("\r\n\r\n")){
                        Map headers = new HashMap<String,String>();
                        for(String header:res.split("\r\n")){
                            if(header.contains(":")){
                                String reqHeaderKey = header.substring(0,header.indexOf(":")).trim();
                                String reqHeaderValue = header.substring(header.indexOf(":")+1,header.length()).trim();
                                headers.put(reqHeaderKey,reqHeaderValue);
                            }
                        }

                        if(headers.containsKey("Content-Length")){
                            contentLength = Integer.valueOf((String)headers.get("Content-Length"));
                        }else if(headers.containsKey("Transfer-Encoding") && headers.get("Transfer-Encoding").equals("chunked")){
                            isChunked = true;
                        }
                        proccessedHeader = true;
                    }

                    if(isChunked && res.endsWith("\r\n0\r\n\r\n")){
                        break;
                    }else if(contentLength != 0){
                        if(acceptedLength == contentLength){
                            break;
                        }
                        acceptedLength++;
                    }
                }

                //未知协议
                if (flag == -1) {
                    break;
                }
            }catch (Throwable t){
                t.printStackTrace();
                break;
            }
        }
        return readedContent;
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

    /**
     * 检测Weblogic过滤器状态
     * @param helloMsg hello返回包
     * @return 过滤器是否开启
     */
    public static boolean isFilterEnable(String helloMsg){
        if(
            (helloMsg.contains("Connection rejected") || helloMsg.contains("filter blocked Socket"))
            && helloMsg.contains("weblogic.security.net.FilterException")
            && helloMsg.contains("Security:090220")
        ){
            return true;
        }else{
            return false;
        }
    }

}
