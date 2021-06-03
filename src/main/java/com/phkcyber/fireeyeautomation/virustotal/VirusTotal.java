package com.phkcyber.fireeyeautomation.virustotal;

import java.io.BufferedReader;
import java.io.FileWriter;
import java.io.FileNotFoundException;
import java.io.File;

import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.net.URL;

import javax.net.ssl.HttpsURLConnection;

import java.util.*;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

import org.apache.commons.codec.binary.Base64;

public class VirusTotal {
  private Map<String,String> requestHeaders = new HashMap<>();
  private static final String apiKey="daa6a4f57ea25d63ec66541f280b3f7a997dc1ed78fd0e8ec7d1f7d5a4bdd0bb";
  private static final String baseUrl="https://www.virustotal.com/api/v3/files";

  //basic constructor
  public VirusTotal() {
    requestHeaders.put("X-Apikey", apiKey);
  }

  //search VT, write the JSON to a file, return the full path to the file
  public String search(String hash) throws FileNotFoundException,Exception {
    String urlStr = baseUrl + "/" + hash;    

    //get the data from VT
    String resp = httpClient(urlStr, "GET", requestHeaders, null);

    //convert the text into a JSN object
    Gson gson = new GsonBuilder().setPrettyPrinting().create();
    VTResponse vtJson = gson.fromJson(resp, VTResponse.class);

    //write the pretty formatted JSON to a temp file
    File tempFile = File.createTempFile("fireeye-", "-virustotal");

    FileWriter writer = new FileWriter(tempFile);
    gson.toJson(vtJson, writer);
    writer.close();

    //return the full path to the JSON file for attachment to the email
    return(tempFile.getAbsolutePath());
  }


  //http client to download data from VT
  public String httpClient(String urlStr, String method, Map<String,String> requestHeaders, String data) throws Exception {

    Map<String,String> response = new HashMap<>();

    //logger.log(Level.INFO, "Connecting to URL " + urlStr);
    System.out.println("Connecting to URL " + urlStr);
    URL url = new URL(urlStr);
    HttpsURLConnection conn = (HttpsURLConnection) url.openConnection();
    ////conn.setSSLSocketFactory(getSocketFactory());
    //conn.setSSLSocketFactory( (SSLSocketFactory)CustomSocketFactory.getDefault() );
    conn.setRequestMethod(method);
    conn.setDoOutput(true);
    conn.setDoInput(true);
    conn.setUseCaches(false);
    conn.setAllowUserInteraction(false);

    if(requestHeaders != null) {
      for(String header : requestHeaders.keySet()) {
        conn.setRequestProperty(header, requestHeaders.get(header));
      }
    }

    // Create POST/PUT data
    if( ("POST".equals(method) || "PUT".equals(method)) && data != null) {
      OutputStream out = conn.getOutputStream();
      Writer writer = new OutputStreamWriter(out, "UTF-8");
      writer.write(data);

      writer.close();
      out.close();
    }

    if (conn.getResponseCode() == 401) {
      throw new Exception("401");
    }
    else if (conn.getResponseCode() == 403) {
      throw new Exception("403");
    }
    else {
        response.put("response_code", Integer.toString(conn.getResponseCode()) );
    }

    //read response headers
//    if(responseHeaders != null) {
//        for(String header : responseHeaders.keySet()) {
//                response.put(header, conn.getHeaderField(header));
//        }
//    }

    // Buffer the result into a string
    BufferedReader rd = new BufferedReader(
      new InputStreamReader(conn.getInputStream()));

    StringBuilder sb = new StringBuilder();
    String line;

    while ((line = rd.readLine()) != null) {
      sb.append(line);
    }
    rd.close();

    ////put data in response
    ////logger.log(Level.FINE, sb.toString());
    //response.put("data", sb.toString());
    conn.disconnect();

    //return(response);
    return(sb.toString());

  }

}
