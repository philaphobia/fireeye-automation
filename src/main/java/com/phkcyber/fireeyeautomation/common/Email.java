package com.phkcyber.fireeyeautomation.common;


import java.util.*;

import javax.mail.*;
import javax.mail.internet.*;
import javax.activation.*;

public class Email {
  private final String smtpHost = "";
	
  private List<String> recipientTo=null;
  private List<String> recipientCc=null;
  private List<String> recipientBcc=null;
  private HashMap<String,String> attachments=null;
  private String sender=null;
  private String subject=null;
  private String body=null;

  public Email() {
  }
  
  public void addTo(List<String> to) {
    this.recipientTo = to;
  }
  public void addCc(List<String> cc) {
    this.recipientCc = cc;
  }
  public void addBcc(List<String> bcc) {
    this.recipientBcc = bcc;
  }
  public void addFrom(String sender) {
    this.sender = sender; 
  }
  public void addSubject(String subject) {
    this.subject = subject; 
  }
  public void addBody(String body) {
    this.body = body; 
  }
  public void addAttachments(HashMap<String,String> attachments) {
    this.attachments = attachments; 
  }

  public void sendMessage() {
    // Get system properties
    Properties props = System.getProperties();

    // Setup mail server
    props.setProperty("mail.smtp.host", smtpHost);

    // Get the default Session object.
    Session session = Session.getDefaultInstance(props);

    try{
      // Create a default MimeMessage object.
      MimeMessage message = new MimeMessage(session);

      // Set From: header field of the header.
      message.setFrom(new InternetAddress(sender));

      // Set To: header field of the header.
      for(String to : recipientTo)
        message.addRecipient(Message.RecipientType.TO, new InternetAddress(to));

      // Set Cc: header field of the header.
      if(recipientCc != null) {
        for(String cc : recipientCc)
          message.addRecipient(Message.RecipientType.CC, new InternetAddress(cc));
      }

      // Set Bcc: header field of the header.
      if(recipientBcc != null) {
        for(String bcc : recipientBcc)
          message.addRecipient(Message.RecipientType.BCC, new InternetAddress(bcc));
      }

      // Set Subject: header field
      message.setSubject(subject);

      //create body
      //add <pre> tag to avoid loading dangerous data
      String bodySafe = "<pre>" + body + "</pre>";
      //message.setContent(bodySafe, "text/html");
      
      
      // Create a multipart message
      Multipart multipart = new MimeMultipart();

      // Create the message part 
      MimeBodyPart messageBodyPart = new MimeBodyPart();
      messageBodyPart.setContent(bodySafe, "text/html");
         

      // Set text message part
      multipart.addBodyPart(messageBodyPart);


      if(attachments != null) {
        for(String filePath : attachments.keySet()) {
          if(filePath == null)
            continue;
 
          String fileName = attachments.get(filePath);
           
          //only add attachment if the file path is not null
          if( (fileName != null) && (filePath != null) ) {
            //part is attachment
            MimeBodyPart attachPart = new MimeBodyPart();
	   
            DataSource source = new FileDataSource(filePath);
            attachPart.setDataHandler(new DataHandler(source));
            attachPart.setFileName(fileName);
            multipart.addBodyPart(attachPart);
          }
        }
      }

      // Set the complete message parts
      message.setContent(multipart);
	

      // Send message
      Transport.send(message);
    }
    catch (MessagingException mex) {
      mex.printStackTrace();
    }
  }

}
