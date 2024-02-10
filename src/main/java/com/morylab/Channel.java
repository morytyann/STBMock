package com.morylab;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class Channel {
    private String name;
    private String url;

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getUrl() {
        return url;
    }

    public void setUrl(String url) {
        this.url = url;
    }

    private static final String nameRegex = "(?<=ChannelName=\").+?(?=\")";
    private static final String urlRegex = "(?<=ChannelURL=\").+?(?=\")";

    public static Channel parse(String line) {
        Channel channel = new Channel();
        Pattern pattern;
        Matcher matcher;
        // 解析name
        pattern = Pattern.compile(nameRegex);
        matcher = pattern.matcher(line);
        if (matcher.find()) {
            channel.setName(matcher.group());
        }
        // 解析url
        pattern = Pattern.compile(urlRegex);
        matcher = pattern.matcher(line);
        if (matcher.find()) {
            channel.setUrl(matcher.group());
        }
        return channel;
    }
}
