package com.morylab;

import cn.hutool.http.HttpUtil;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;

public class Main {
    // 加解密参数
    private static final byte[] keyForSecretKey = new byte[]{31, -64, 37, 65, -50, 37, 106, -121, 75, 33, 99, 35, 37, 115, 108, -82};
    private static final String textForSecretKey = "0C4fiyTCHTNMECO/qs8jw5VvEY28xxFP9Rfgk51i+pE=";
    private static final byte[] secretKey = md5Digest(aesDecrypt(keyForSecretKey, Base64.getDecoder().decode(textForSecretKey)));
    // iptv账号密码
    private static final String iptvAccount = "";
    private static final String iptvPasswordEncrypted = "";
    private static final String iptvPassword = new String(aesDecrypt(secretKey, Base64.getDecoder().decode(iptvPasswordEncrypted)));
    // 设备信息
    private static final String stbModel = "";
    private static final String stbId = "";
    private static final String stbVersion = "";
    private static final String stbIp = "";
    private static final String stbMac = "";
    private static final String stbInfo = "";
    private static final String platform = "$CTC";
    // 服务器
    private static final String easIP = "124.132.240.38";
    private static final int easPort = 8080;
    private static final String epgIP = "112.232.164.205";
    private static final int epgPort = 8080;
    // UDPXY地址
    private static final String udpxyPrefix = "http://192.168.1.1:4022/";

    public static void main(String[] args) {
        step1();
        String encryptToken = step2();
        String authenticator = generateAuthenticator(encryptToken);
        String functionIndexUrl = step3(authenticator);
        Map<String, String> functionIndexQueryMap = parseQuery(functionIndexUrl.substring(functionIndexUrl.indexOf("?")));
        String userToken = functionIndexQueryMap.get("UserToken");
        step4(functionIndexUrl);
        step5(userToken);
        List<Channel> channels = step6();
        String m3u = generateM3U(channels);
        System.out.println(m3u);
    }

    private static void step1() {
        String url = "http://" + easIP + ":" + easPort + "/iptvepg/platform/index.jsp?UserID=" + iptvAccount + "&Action=Login";
        HttpUtil.get(url);
    }

    private static String step2() {
        String result = null;
        String url = "http://" + easIP + ":" + easPort + "/iptvepg/platform/getencrypttoken.jsp";
        // query
        Map<String, String> queries = new HashMap<>();
        queries.put("UserID", iptvAccount);
        queries.put("Action", "Login");
        queries.put("TerminalFlag", "1");
        queries.put("TerminalOsType", "0");
        queries.put("STBID", "");
        queries.put("stbtype", "");
        // 请求
        String response = HttpUtil.get(url + generateQuery(queries));
        // 解析
        String[] lines = response.split("\n");
        for (String line : lines) {
            if (line.contains("GetAuthInfo")) {
                result = line.substring(line.indexOf("'") + 1, line.lastIndexOf("'"));
                break;
            }
        }
        // 返回
        return result;
    }

    private static String step3(String authenticator) {
        String result = null;
        String url = "http://" + epgIP + ":" + epgPort + "/iptvepg/platform/auth.jsp";
        // query
        Map<String, String> queries = new HashMap<>();
        queries.put("easip", easIP);
        queries.put("ipVersion", "4");
        queries.put("networkid", "1");
        queries.put("serterminalno", "199");
        // body
        Map<String, Object> params = new HashMap<>();
        params.put("UserID", iptvAccount);
        params.put("Authenticator", authenticator);
        params.put("StbIP", stbIp);
        // 请求
        String response = HttpUtil.post(url + generateQuery(queries), params);
        // 解析
        String[] lines = response.split("\n");
        for (String line : lines) {
            if (line.contains("window.location")) {
                result = line.substring(line.indexOf("'") + 1, line.lastIndexOf("'"));
                break;
            }
        }
        // 返回
        return result;
    }

    private static void step4(String url) {
        HttpUtil.get(url);
    }

    private static void step5(String userToken) {
        String url = "http://" + epgIP + ":" + epgPort + "/iptvepg/function/funcportalauth.jsp";
        // body
        Map<String, Object> params = new HashMap<>();
        params.put("UserToken", userToken);
        params.put("UserID", iptvAccount);
        params.put("STBID", stbId);
        params.put("stbtype", stbModel);
        params.put("stbversion", stbVersion);
        params.put("stbinfo", stbInfo);
        params.put("easip", easIP);
        params.put("networkid", "1");
//        params.put("prmid", "");
//        params.put("drmsupplier", "");
        // 请求
        HttpUtil.post(url, params);
    }

    private static List<Channel> step6() {
        List<Channel> channels = new ArrayList<>();
        String url = "http://" + epgIP + ":" + epgPort + "/iptvepg/function/frameset_builder.jsp";
        // body
        Map<String, Object> params = new HashMap<>();
        params.put("MAIN_WIN_SRC", "/iptvepg/frame205/channel_start.jsp?tempno=-1");
        params.put("NEED_UPDATE_STB", "1");
        params.put("BUILD_ACTION", "FRAMESET_BUILDER");
//        params.put("hdmistatus", "");
        // 请求
        String response = HttpUtil.post(url, params);
        // 解析
        String[] lines = response.split("\n");
        for (String line : lines) {
            if (line.contains("jsSetConfig") && line.contains("'Channel'")) {
                channels.add(Channel.parse(line));
            }
        }
        // 返回
        return channels;
    }

    /**
     * 生成Authenticator
     */
    private static String generateAuthenticator(String encryptToken) {
        // 生成key
        int authenticatorKeyLength = 24;
        byte[] iptvPasswordBytes = iptvPassword.getBytes();
        byte[] authenticatorKey = new byte[authenticatorKeyLength];
        for (int i = 0; i < authenticatorKeyLength; i++) {
            authenticatorKey[i] = i < iptvPasswordBytes.length ? iptvPasswordBytes[i] : 48;
        }
        // 生成原文
        long random = (long) (Math.random() * 10000000L);
        String originalText = String.format("%08d", random);
        originalText += "$" + encryptToken;
        originalText += "$" + iptvAccount;
        originalText += "$" + stbId;
        originalText += "$" + stbIp;
        originalText += "$" + stbMac;
        originalText += "$" + platform;
        // 生成密文
        byte[] authenticatorBytes = desEncrypt(authenticatorKey, originalText.getBytes());
        // HexString
        StringBuilder authenticatorBuilder = new StringBuilder();
        for (byte b : authenticatorBytes) {
            authenticatorBuilder.append(String.format("%02X", b < 0 ? b + 256 : b));
        }
        return authenticatorBuilder.toString();
    }

    /**
     * 生成播放列表
     */
    private static String generateM3U(List<Channel> channels) {
        StringBuilder builder = new StringBuilder("#EXTM3U");
        builder.append("\n");
        for (Channel channel : channels) {
            builder.append("\n");
            builder.append("#EXTINF:-1,").append(channel.getName());
            builder.append("\n");
            builder.append(udpxyPrefix).append(channel.getUrl().replace("igmp://", "udp/")).append("/");
            builder.append("\n");
        }
        return builder.toString();
    }

    /**
     * 解析query
     */
    private static Map<String, String> parseQuery(String query) {
        if (query.startsWith("?")) {
            query = query.substring(1);
        }
        Map<String, String> queries = new HashMap<>();
        for (String s : query.split("&")) {
            String[] kv = s.split("=");
            queries.put(kv[0], kv.length > 1 ? kv[1] : "");
        }
        return queries;
    }

    /**
     * 生成query
     */
    private static String generateQuery(Map<String, String> queries) {
        StringJoiner joiner = new StringJoiner("&", "?", "");
        queries.forEach((k, v) -> joiner.add(k + "=" + v));
        return joiner.toString();
    }

    /**
     * DES加密
     */
    private static byte[] desEncrypt(byte[] key, byte[] bytes) {
        try {
            SecretKeySpec keySpec = new SecretKeySpec(key, "DESede");
            Cipher cipher = Cipher.getInstance("DESede/ECB/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, keySpec);
            return cipher.doFinal(bytes);
        } catch (GeneralSecurityException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * DES解密
     */
    private static byte[] desDecrypt(byte[] key, byte[] bytes) {
        try {
            SecretKeySpec keySpec = new SecretKeySpec(key, "DESede");
            Cipher cipher = Cipher.getInstance("DESede/ECB/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, keySpec);
            return cipher.doFinal(bytes);
        } catch (GeneralSecurityException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * AES加密
     */
    private static byte[] aesEncrypt(byte[] key, byte[] bytes) {
        try {
            SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, keySpec);
            return cipher.doFinal(bytes);
        } catch (GeneralSecurityException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * AES解密
     */
    private static byte[] aesDecrypt(byte[] key, byte[] bytes) {
        try {
            SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, keySpec);
            return cipher.doFinal(bytes);
        } catch (GeneralSecurityException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * MD5摘要
     */
    private static byte[] md5Digest(byte[] bytes) {
        try {
            MessageDigest md5 = MessageDigest.getInstance("MD5");
            md5.update(bytes);
            return md5.digest();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

}
