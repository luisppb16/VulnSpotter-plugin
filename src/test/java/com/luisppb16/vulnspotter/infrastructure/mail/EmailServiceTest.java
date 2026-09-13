/*
 * *****************************************************************************
 * Copyright (c)  2026 Luis Paolo Pepe Barra (@LuisPPB16).
 * All rights reserved.
 * *****************************************************************************
 */

package com.luisppb16.vulnspotter.infrastructure.mail;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;

import com.intellij.openapi.Disposable;
import jakarta.mail.MessagingException;
import jakarta.mail.internet.InternetAddress;
import jakarta.mail.internet.MimeMessage;
import java.time.Duration;
import java.util.Locale;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@DisplayName("EmailService Test Suite")
@ExtendWith(MockitoExtension.class)
class EmailServiceTest {

  private static final Duration FUTURE_TIMEOUT = Duration.ofSeconds(5);
  private static final String HOST = "smtp.example.com";
  private static final int PORT = 587;
  private static final String USERNAME = "alerts@example.com";
  private static final String PASSWORD = "";
  private static final String RECIPIENT = "dev-team@example.com";
  private static final String SUBJECT = "VulnSpotter alert";
  private static final String BODY = "<h1>Vulnerabilities found</h1>";

  @Mock private MailTransport transport;

  private ExecutorService executor;
  private EmailService service;

  @BeforeEach
  void setUp() {
    executor = Executors.newSingleThreadExecutor();
    service = new EmailService(transport, executor);
  }

  @AfterEach
  void tearDown() {
    executor.shutdownNow();
  }

  @Test
  @DisplayName("should_reject_blank_host")
  void shouldRejectBlankHost() {
    // Given
    String host = "   ";

    // When / Then
    assertThatThrownBy(() -> new SmtpConfig(host, PORT, SmtpSecurity.STARTTLS, RECIPIENT))
        .isInstanceOf(IllegalArgumentException.class);
  }

  @Test
  @DisplayName("should_reject_null_host")
  void shouldRejectNullHost() {
    // When / Then
    assertThatThrownBy(() -> new SmtpConfig(null, PORT, SmtpSecurity.STARTTLS, RECIPIENT))
        .isInstanceOf(IllegalArgumentException.class);
  }

  @ParameterizedTest
  @ValueSource(ints = {0, -1, 65536, 70000})
  @DisplayName("should_reject_out_of_range_port")
  void shouldRejectOutOfRangePort(int port) {
    // When / Then
    assertThatThrownBy(() -> new SmtpConfig(HOST, port, SmtpSecurity.STARTTLS, RECIPIENT))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("port");
  }

  @Test
  @DisplayName("should_reject_null_security")
  void shouldRejectNullSecurity() {
    // When / Then
    assertThatThrownBy(() -> new SmtpConfig(HOST, PORT, null, RECIPIENT))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("security");
  }

  @ParameterizedTest
  @ValueSource(strings = {"", "   "})
  @DisplayName("should_reject_blank_recipient")
  void shouldRejectBlankRecipient(String recipient) {
    // When / Then
    assertThatThrownBy(() -> new SmtpConfig(HOST, PORT, SmtpSecurity.STARTTLS, recipient))
        .isInstanceOf(IllegalArgumentException.class);
  }

  @Test
  @DisplayName("should_reject_recipient_without_at_sign")
  void shouldRejectRecipientWithoutAtSign() {
    // Given
    String recipient = "not-an-email";

    // When / Then
    assertThatThrownBy(() -> new SmtpConfig(HOST, PORT, SmtpSecurity.STARTTLS, recipient))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("recipient");
  }

  @Test
  @DisplayName("should_reject_null_password_when_username_set")
  void shouldRejectNullPasswordWhenUsernameSet() {
    // When / Then
    assertThatThrownBy(
            () -> new SmtpConfig(HOST, PORT, SmtpSecurity.STARTTLS, USERNAME, null, RECIPIENT))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("password");
  }

  @ParameterizedTest
  @ValueSource(strings = {"NONE", "starttls", "SSL  ", "  none"})
  @DisplayName("should_resolve_security_from_case_insensitive_label")
  void shouldResolveSecurityFromLabel(String label) {
    // When
    SmtpSecurity security = SmtpSecurity.fromLabel(label);

    // Then
    assertThat(security).isEqualTo(SmtpSecurity.valueOf(label.trim().toUpperCase(Locale.ROOT)));
  }

  @Test
  @DisplayName("should_fail_fast_on_blank_security_label")
  void shouldFailFastOnBlankSecurityLabel() {
    // When / Then
    assertThatThrownBy(() -> SmtpSecurity.fromLabel("  "))
        .isInstanceOf(IllegalArgumentException.class);
  }

  @Test
  @DisplayName("should_fail_fast_on_unknown_security_label")
  void shouldFailFastOnUnknownSecurityLabel() {
    // When / Then
    assertThatThrownBy(() -> SmtpSecurity.fromLabel("TLS"))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("TLS");
  }

  @Test
  @DisplayName("buildMessage_uses_username_as_sender_when_auth_required")
  void shouldUseUsernameAsSenderWhenAuthRequired() throws Exception {
    // Given
    SmtpConfig config =
        new SmtpConfig(HOST, PORT, SmtpSecurity.STARTTLS, USERNAME, PASSWORD, RECIPIENT);

    // When
    MimeMessage message = service.buildMessage(config, SUBJECT, BODY);

    // Then
    assertThat(message.getFrom()).hasSize(1);
    assertThat(((InternetAddress) message.getFrom()[0]).getAddress()).isEqualTo(USERNAME);
    assertThat(message.getRecipients(MimeMessage.RecipientType.TO))
        .extracting(address -> ((InternetAddress) address).getAddress())
        .containsExactly(RECIPIENT);
    assertThat(message.getSubject()).isEqualTo(SUBJECT);
    assertThat(message.getContentType()).contains("text/html");
    assertThat(message.getSentDate()).isNotNull();
  }

  @Test
  @DisplayName("buildMessage_uses_recipient_as_sender_when_no_auth")
  void shouldUseRecipientAsSenderWhenNoAuth() throws Exception {
    // Given
    SmtpConfig config = new SmtpConfig(HOST, PORT, SmtpSecurity.STARTTLS, null, null, RECIPIENT);

    // When
    MimeMessage message = service.buildMessage(config, SUBJECT, BODY);

    // Then
    assertThat(config.requiresAuth()).isFalse();
    assertThat(((InternetAddress) message.getFrom()[0]).getAddress()).isEqualTo(RECIPIENT);
    InternetAddress to = (InternetAddress) message.getRecipients(MimeMessage.RecipientType.TO)[0];
    assertThat(to.getAddress()).isEqualTo(RECIPIENT);
  }

  @Test
  @DisplayName("sendVulnerabilityAlert_connects_sends_and_completes_true")
  void shouldSendAlertAndCompleteTrue() throws Exception {
    // Given
    SmtpConfig config =
        new SmtpConfig(HOST, PORT, SmtpSecurity.STARTTLS, USERNAME, PASSWORD, RECIPIENT);

    // When
    CompletableFuture<Boolean> future = service.sendVulnerabilityAlert(config, SUBJECT, BODY);

    // Then
    assertThat(future).succeedsWithin(FUTURE_TIMEOUT).isEqualTo(true);
    verify(transport).connect(config);
    ArgumentCaptor<MimeMessage> captor = ArgumentCaptor.forClass(MimeMessage.class);
    verify(transport).sendMessage(captor.capture());
    assertThat(captor.getValue().getSubject()).isEqualTo(SUBJECT);
    verify(transport).close();
  }

  @Test
  @DisplayName("sendVulnerabilityAlert_fails_fast_on_null_arguments")
  void shouldFailFastOnNullArguments() {
    // Given
    SmtpConfig config =
        new SmtpConfig(HOST, PORT, SmtpSecurity.STARTTLS, USERNAME, PASSWORD, RECIPIENT);

    // When / Then
    assertThatThrownBy(() -> service.sendVulnerabilityAlert(null, SUBJECT, BODY))
        .isInstanceOf(IllegalArgumentException.class);
    assertThatThrownBy(() -> service.sendVulnerabilityAlert(config, null, BODY))
        .isInstanceOf(IllegalArgumentException.class);
    assertThatThrownBy(() -> service.sendVulnerabilityAlert(config, SUBJECT, null))
        .isInstanceOf(IllegalArgumentException.class);
    verifyNoInteractions(transport);
  }

  @Test
  @DisplayName("sendVulnerabilityAlert_completes_exceptionally_and_closes_when_connect_fails")
  void shouldCompleteExceptionallyWhenConnectFails() throws Exception {
    // Given
    SmtpConfig config =
        new SmtpConfig(HOST, PORT, SmtpSecurity.STARTTLS, USERNAME, PASSWORD, RECIPIENT);
    MessagingException failure = new MessagingException("connect refused");
    doThrow(failure).when(transport).connect(config);

    // When
    CompletableFuture<Boolean> future = service.sendVulnerabilityAlert(config, SUBJECT, BODY);

    // Then
    assertThatThrownBy(() -> future.get(FUTURE_TIMEOUT.toSeconds(), TimeUnit.SECONDS))
        .hasCause(failure);
    verify(transport).connect(config);
    verify(transport).close();
  }

  @Test
  @DisplayName("sendVulnerabilityAlert_closes_transport_even_when_send_fails")
  void shouldCloseTransportEvenWhenSendFails() throws Exception {
    // Given
    SmtpConfig config =
        new SmtpConfig(HOST, PORT, SmtpSecurity.STARTTLS, USERNAME, PASSWORD, RECIPIENT);
    doThrow(new MessagingException("send failed"))
        .when(transport)
        .sendMessage(any(MimeMessage.class));

    // When
    CompletableFuture<Boolean> future = service.sendVulnerabilityAlert(config, SUBJECT, BODY);

    // Then
    assertThatThrownBy(() -> future.get(FUTURE_TIMEOUT.toSeconds(), TimeUnit.SECONDS))
        .hasCauseInstanceOf(MessagingException.class);
    verify(transport).close();
  }

  @Test
  @DisplayName("dispose_shuts_down_executor_without_throwing")
  void shouldShutdownExecutorOnDispose() {
    // Given
    ExecutorService ownedExecutor = Executors.newSingleThreadExecutor();
    EmailService ownedService = new EmailService(transport, ownedExecutor);

    // When
    ownedService.dispose();

    // Then
    assertThat(ownedExecutor.isShutdown()).isTrue();
  }

  @Test
  @DisplayName("dispose_through_disposable_does_not_throw")
  void shouldDisposeThroughDisposableWithoutThrowing() {
    // Given
    ExecutorService ownedExecutor = Executors.newSingleThreadExecutor();
    EmailService ownedService = new EmailService(transport, ownedExecutor);
    Disposable disposable = ownedService;

    // When / Then
    assertThatCode(disposable::dispose).doesNotThrowAnyException();

    // Then
    assertThat(ownedExecutor.isShutdown()).isTrue();
  }
}
