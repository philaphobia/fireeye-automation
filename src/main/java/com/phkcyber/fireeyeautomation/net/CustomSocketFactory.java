package com.phkcyber.fireeyeautomation.net;

import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;
import java.net.UnknownHostException;

import javax.net.SocketFactory;
import javax.net.ssl.*;

import java.util.logging.Logger;

import java.security.*;
import java.security.cert.X509Certificate;


public class CustomSocketFactory extends SSLSocketFactory {
  private static final Logger logger = Logger.getLogger("CustomSocketFactory");
  private static TrustManager[] trustAllCerts=null;
  private static HostnameVerifier hv=null;
  private static SSLSocketFactory ssf=null;
  private Boolean _error=false;
  private String _errorMsg="";

  
  public CustomSocketFactory() {
	super();

	logger.fine("Instantiating the custom socket factory");

    trustAllCerts = new TrustManager[] {
      new X509TrustManager() {
        public java.security.cert.X509Certificate[] getAcceptedIssuers() {
          return null;
        }
        public void checkClientTrusted(X509Certificate[] certs, String authType) {
        }
        public void checkServerTrusted(X509Certificate[] certs, String authType) {
        }
      }
    };

    hv = new HostnameVerifier() {
      public boolean verify(String urlHostName, SSLSession session) {
        if (!urlHostName.equalsIgnoreCase(session.getPeerHost())) {
          System.out.println("Warning: URL host '" + urlHostName + "' is different to SSLSession host '" + session.getPeerHost() + "'.");
        }
        return true;
      }
    };
   
 
    try {
      //get the SSL context
      SSLContext sc = SSLContext.getInstance("TLS");
      if(sc == null)
        throw new Exception("SSLContext returned null");

      sc.init(new KeyManager[0], trustAllCerts, new SecureRandom());

      //get the ssl socket factory
      ssf = sc.getSocketFactory();
      if(ssf == null)
        throw new Exception("SSLSocketFactory returned null");

      HttpsURLConnection.setDefaultSSLSocketFactory(ssf); 
      HttpsURLConnection.setDefaultHostnameVerifier(hv); 
    }
    catch(NoSuchAlgorithmException nsae) {
      logger.severe("SSLFactory threw NoSuchAlgoritmException: " + nsae.getMessage());
      _error = true;
      _errorMsg = "SSLFactory threw NoSuchAlgoritmException: " + nsae.getMessage();
    }
    catch(KeyManagementException kme) {
      logger.severe("SSLFactory threw KeyManagementException: " + kme.getMessage());
      _error = true;
      _errorMsg = "SSLFactory threw KeyManagementException: " + kme.getMessage();
    }
    catch(Exception e) {
      logger.severe("SSLFactory threw Exception: " + e.getMessage());
      _error = true;
      _errorMsg = "SSLFactory threw Exception: " + e.getMessage();
    }
  }


  public static SocketFactory getDefault() {
    return new CustomSocketFactory();
  }


  public Socket createSocket(String host, int port) throws IOException, UnknownHostException {
    if(_error)
      throw new IOException(_errorMsg);
 
    logger.fine("Creating a custom socket (method 1)");
        
    return(ssf.createSocket(host,port)); 
  }

  public Socket createSocket(String host, int port, InetAddress localHost, int localPort) throws IOException, UnknownHostException {
    if(_error)
      throw new IOException(_errorMsg);

    logger.fine("Creating a custom socket (method 2)");

    return(ssf.createSocket(host,port,localHost,localPort)); 
  }

  public Socket createSocket(InetAddress address, int port) throws IOException {
    if(_error)
      throw new IOException(_errorMsg);

    logger.fine("Creating a custom socket (method 3)]");

    return(ssf.createSocket(address,port)); 
  }


  public Socket createSocket(InetAddress address, int port, InetAddress localAddress, int localPort) throws IOException {
    if(_error)
      throw new IOException(_errorMsg);

    logger.fine("Creating a custom socket (method 4)");

    return(ssf.createSocket(address,port,localAddress,localPort)); 
  }

  @Override
  public Socket createSocket(Socket s, String host, int port, boolean autoClose) throws IOException {
	    if(_error)
	        throw new IOException(_errorMsg);

	      logger.fine("Creating a custom socket (method 5)");

	      return(createSocket(host,port)); 
  }

  
  @Override
  public String[] getDefaultCipherSuites() {
	return null;
  }


  @Override 
  public String[] getSupportedCipherSuites() {
	return null;
  }

}
