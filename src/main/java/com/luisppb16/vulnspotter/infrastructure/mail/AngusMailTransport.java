/*
 * *****************************************************************************
 * Copyright (c)  2026 Luis Paolo Pepe Barra (@LuisPPB16).
 * All rights reserved.
 * *****************************************************************************
 */

package com.luisppb16.vulnspotter.infrastructure.mail;

import jakarta.mail.MessagingException;
import jakarta.mail.Session;
import jakarta.mail.Transport;
import jakarta.mail.internet.MimeMessage;
import java.util.Properties;

/** {@link MailTransport} implementation backed by the Angus Mail (Jakarta Mail) library. */
public final class AngusMailTransport implements MailTransport {

  private static final int CONNECTION_TIMEOUT_MS = 10000;
  private static final int READ_TIMEOUT_MS = 15000;
  private static final int WRITE_TIMEOUT_MS = 15000;

  private Transport transport;

  @Override
  public void connect(SmtpConfig config) throws MessagingException {
    Session session = Session.getInstance(buildProperties(config));
    transport = session.getTransport("smtp");
    try {
      if (config.requiresAuth()) {
        transport.connect(config.host(), config.port(), config.username(), config.password());
      } else {
        transport.connect(config.host(), config.port(), null, null);
      }
    } catch (MessagingException ex) {
      // A failed connect leaves the transport unusable: release it and rethrow the cause.
      closeQuietly(transport);
      transport = null;
      throw ex;
    }
  }

  @Override
  public void sendMessage(MimeMessage message) throws MessagingException {
    if (transport == null || !transport.isConnected()) {
      throw new MessagingException("SMTP transport is not connected");
    }
    transport.sendMessage(message, message.getAllRecipients());
  }

  /** Best-effort close: errors while releasing an already-used transport are not actionable. */
  @Override
  public void close() {
    Transport current = transport;
    transport = null;
    closeQuietly(current);
  }

  private static Properties buildProperties(SmtpConfig config) {
    Properties props = new Properties();
    props.put("mail.smtp.host", config.host());
    props.put("mail.smtp.port", String.valueOf(config.port()));
    props.put("mail.smtp.auth", String.valueOf(config.requiresAuth()));
    props.put("mail.smtp.connectiontimeout", String.valueOf(CONNECTION_TIMEOUT_MS));
    props.put("mail.smtp.timeout", String.valueOf(READ_TIMEOUT_MS));
    props.put("mail.smtp.writetimeout", String.valueOf(WRITE_TIMEOUT_MS));
    switch (config.security()) {
      case STARTTLS -> props.put("mail.smtp.starttls.enable", "true");
      case SSL -> props.put("mail.smtp.ssl.enable", "true");
      case NONE -> {
        // No TLS properties for a plain connection.
      }
    }
    return props;
  }

  private static void closeQuietly(Transport transport) {
    if (transport == null) {
      return;
    }
    try {
      if (transport.isConnected()) {
        transport.close();
      }
    } catch (MessagingException ignored) {
      // Swallow on purpose: closing is best-effort, real failures surface during connect/send.
    }
  }
}