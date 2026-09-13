/*
 * *****************************************************************************
 * Copyright (c)  2026 Luis Paolo Pepe Barra (@LuisPPB16).
 * All rights reserved.
 * *****************************************************************************
 */

package com.luisppb16.vulnspotter.infrastructure.mail;

import com.intellij.openapi.Disposable;
import com.intellij.openapi.application.ApplicationManager;
import com.intellij.openapi.components.Service;
import com.intellij.openapi.diagnostic.Logger;
import jakarta.mail.Message;
import jakarta.mail.MessagingException;
import jakarta.mail.Session;
import jakarta.mail.internet.InternetAddress;
import jakarta.mail.internet.MimeMessage;
import java.util.Date;
import java.util.Properties;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import org.jetbrains.annotations.TestOnly;

/**
 * Application-level service that sends vulnerability alert emails over SMTP. Deliveries run on a
 * dedicated daemon thread so the UI thread is never blocked by network I/O; the returned future
 * carries the outcome to the caller.
 */
@Service
public final class EmailService implements Disposable {

  private static final Logger LOG = Logger.getInstance(EmailService.class);
  private static final String THREAD_NAME = "VulnSpotter-Mail";
  private static final String HTML_CONTENT_TYPE = "text/html; charset=utf-8";

  private final MailTransport transport;
  private final ExecutorService executor;

  /** Constructor used by the IntelliJ Platform to instantiate the application service. */
  public EmailService() {
    this(new AngusMailTransport(), newMailExecutor());
  }

  /**
   * Test-only constructor that injects the transport and the executor instead of the real ones.
   * Production code must rely on {@link #EmailService()}.
   */
  @TestOnly
  public EmailService(MailTransport transport, ExecutorService executor) {
    if (transport == null) {
      throw new IllegalArgumentException("transport must not be null");
    }
    if (executor == null) {
      throw new IllegalArgumentException("executor must not be null");
    }
    this.transport = transport;
    this.executor = executor;
  }

  public static EmailService getInstance() {
    return ApplicationManager.getApplication() != null
        ? ApplicationManager.getApplication().getService(EmailService.class)
        : null;
  }

  /**
   * Sends an alert email asynchronously. Fails fast on null arguments; any transport error is
   * surfaced through the returned future, never through a log leak of the SMTP credentials.
   *
   * @param config SMTP connection settings.
   * @param subject email subject.
   * @param body email body, rendered as HTML.
   * @return a future completed with {@code true} on success, or exceptionally with the underlying
   *     {@link MessagingException}/{@link IOException}.
   */
  public CompletableFuture<Boolean> sendVulnerabilityAlert(
      SmtpConfig config, String subject, String body) {
    if (config == null) {
      throw new IllegalArgumentException("config must not be null");
    }
    if (subject == null) {
      throw new IllegalArgumentException("subject must not be null");
    }
    if (body == null) {
      throw new IllegalArgumentException("body must not be null");
    }
    CompletableFuture<Boolean> future = new CompletableFuture<>();
    executor.execute(
        () -> {
          try {
            // close is attempted in the finally even when connect fails; the real transport
            // releases itself on a failed connect, so this stays a safe no-op in that case.
            transport.connect(config);
            transport.sendMessage(buildMessage(config, subject, body));
            future.complete(true);
          } catch (MessagingException ex) {
            LOG.warn(
                "VulnSpotter: email alert delivery to " + config.host() + ":" + config.port()
                    + " failed: " + ex.getMessage());
            future.completeExceptionally(ex);
          } finally {
            transport.close();
          }
        });
    return future;
  }

  /**
   * Builds the MIME message for an alert. Public so tests can inspect the produced message.
   *
   * @param config SMTP settings; the sender is the authenticated username when present, otherwise
   *     the recipient address itself.
   */
  public MimeMessage buildMessage(SmtpConfig config, String subject, String body)
      throws MessagingException {
    // Offline session: no properties, no network lookups, connection is handled by the transport.
    Session session = Session.getInstance(new Properties());
    MimeMessage message = new MimeMessage(session);
    String from = config.requiresAuth() ? config.username() : config.recipient();
    message.setFrom(new InternetAddress(from));
    message.setRecipient(Message.RecipientType.TO, new InternetAddress(config.recipient()));
    message.setSubject(subject, "UTF-8");
    message.setContent(body, HTML_CONTENT_TYPE);
    message.setSentDate(new Date());
    // Materializes the Content-Type/Message-ID headers, so the message is inspectable (and
    // re-sent) without depending on the transport to call saveChanges.
    message.saveChanges();
    return message;
  }

  @Override
  public void dispose() {
    executor.shutdownNow();
  }

  private static ExecutorService newMailExecutor() {
    return Executors.newSingleThreadExecutor(
        runnable -> {
          Thread thread = new Thread(runnable, THREAD_NAME);
          thread.setDaemon(true);
          return thread;
        });
  }
}