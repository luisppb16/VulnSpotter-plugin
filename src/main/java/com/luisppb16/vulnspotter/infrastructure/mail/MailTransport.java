/*
 * *****************************************************************************
 * Copyright (c)  2026 Luis Paolo Pepe Barra (@LuisPPB16).
 * All rights reserved.
 * *****************************************************************************
 */

package com.luisppb16.vulnspotter.infrastructure.mail;

import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;

/** Abstraction over the SMTP transport so email delivery can be mocked in tests. */
public interface MailTransport extends AutoCloseable {

  /** Opens a connection to the SMTP server described by the given configuration. */
  void connect(SmtpConfig config) throws MessagingException;

  /** Sends an already-built message through the connected transport. */
  void sendMessage(MimeMessage message) throws MessagingException;

  /** Closes the transport. Must be safe to call even if no connection was opened. */
  @Override
  void close();
}
