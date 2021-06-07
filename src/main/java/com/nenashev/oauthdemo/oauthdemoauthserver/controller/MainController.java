package com.nenashev.oauthdemo.oauthdemoauthserver.controller;

import com.nenashev.oauthdemo.oauthdemoauthserver.config.OauthConfig;
import com.nenashev.oauthdemo.oauthdemoauthserver.db.AccessTokenRepository;
import com.nenashev.oauthdemo.oauthdemoauthserver.db.RefreshTokenRepository;
import com.nenashev.oauthdemo.oauthdemoauthserver.model.AccessTokenInfo;
import com.nenashev.oauthdemo.oauthdemoauthserver.model.OauthClient;
import com.nenashev.oauthdemo.oauthdemoauthserver.model.RefreshTokenInfo;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.BiConsumer;
import java.util.function.Function;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import javax.servlet.http.HttpServletRequest;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.ui.ModelMap;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.util.UriComponentsBuilder;

import io.jaegertracing.Configuration;
import io.opentracing.Span;
import io.opentracing.SpanContext;
import io.opentracing.Tracer;
import io.opentracing.propagation.Format;
import io.opentracing.propagation.TextMap;
import io.opentracing.propagation.TextMapAdapter;
import static java.util.stream.Collectors.toMap;
import static java.util.stream.Collectors.toSet;

@Controller
@RequestMapping(path = "/")
public class MainController {

    private final Logger logger = LoggerFactory.getLogger(MainController.class);

    private final Base64.Encoder encoder = Base64.getUrlEncoder().withoutPadding();
    private final Base64.Decoder decoder = Base64.getUrlDecoder();

    private final OauthConfig oauthConfig;
    private final SecureRandom secureRandom;
    private final AccessTokenRepository accessTokenRepository;
    private final RefreshTokenRepository refreshTokenRepository;

    private final Map<String, OauthClient> clientsById;

    private final Map<String, Map<String, String>> requestsById = new ConcurrentHashMap<>();

    private final Map<String, Map<String, Object>> codes = new ConcurrentHashMap<>();

    private final Duration tokenMaxAge;

    private final Tracer tracer = Configuration.fromEnv().getTracer();

    public MainController(final OauthConfig oauthConfig,
                          final SecureRandom secureRandom,
                          final AccessTokenRepository accessTokenRepository,
                          final RefreshTokenRepository refreshTokenRepository,
                          @Value("${scheduling.access-token.max-age}") final Duration tokenMaxAge
                         ) {
        this.oauthConfig = oauthConfig;
        this.secureRandom = secureRandom;
        this.accessTokenRepository = accessTokenRepository;
        this.refreshTokenRepository = refreshTokenRepository;
        this.tokenMaxAge = tokenMaxAge;
        this.clientsById = oauthConfig.getClients().stream()
                                      .collect(toMap(OauthClient::getClientId, Function.identity()));

        logger.info("Initialized main controller with OAuth config: {}", oauthConfig);

        this.accessTokenRepository.deleteAll();

        logger.info("Access token database cleared");
    }

    @GetMapping(path = "/")
    public String index(final ModelMap modelMap) {
        modelMap.addAttribute("authServer", oauthConfig);
        return "index";
    }

    @GetMapping(path = "/authorize")
    public String authorize(@RequestParam final Map<String, String> params,
                            final HttpServletRequest request,
                            final ModelMap modelMap
                           ) {
        logger.info("Received GET /authorize with parameters: {}", params);
        final SpanContext parentSpan = tracer.extract(Format.Builtin.TEXT_MAP, new TextMapAdapter(params));
        Tracer.SpanBuilder spanBuilder;
        try {
            if (parentSpan == null) {
                spanBuilder = tracer.buildSpan("authorize-page");
            } else {
                spanBuilder = tracer.buildSpan("authorize-page").asChildOf(parentSpan);
            }
        } catch (final IllegalArgumentException e) {
            spanBuilder = tracer.buildSpan("authorize-page");
        }
        final String reqClientId = params.get("client_id");
        final Span span = spanBuilder
            .withTag("remote_addr", request.getRemoteAddr())
            .withTag("client_id", reqClientId)
            .start();
        span.log("Received GET /authorize");
        span.log(params);

        final OauthClient client = clientsById.get(reqClientId);

        if (client == null) {
            logger.error("Unknown client {}", reqClientId);
            modelMap.addAttribute("error", "Unknown client");
            span.log("Unknown client: " + reqClientId);
            span.finish();
            return "error";
        }

        final String reqRedirectUri = params.get("redirect_uri");
        if (!client.getRedirectUris().contains(reqRedirectUri)) {
            logger.error("Mismatched redirect URI, expected {}, got {}", client.getRedirectUris(), reqRedirectUri);
            modelMap.addAttribute("error", "Invalid redirect URI");
            span.log("Invalid redirect URI: " + reqRedirectUri);
            span.finish();
            return "error";
        }

        final String rScope = params.get("scope");
        final Set<String> reqScope = Stream.of(rScope)
                                           .filter(StringUtils::hasText)
                                           .flatMap(s -> Arrays.stream(s.split(" ")))
                                           .collect(toSet());

        final Set<String> cScope = Stream.of(client.getScope())
                                         .filter(StringUtils::hasText)
                                         .flatMap(s -> Arrays.stream(s.split(" ")))
                                         .collect(toSet());

        if (!cScope.containsAll(reqScope)) {
            logger.error("Invalid scope, expected of {}, got {}", cScope, reqScope);
            final UriComponentsBuilder redirectBuilder = UriComponentsBuilder.fromUriString(reqRedirectUri);
            redirectBuilder.queryParam("error", "invalid_scope");
            span.log("Invalid scope: " + reqScope);
            span.finish();
            return "redirect:" + redirectBuilder.encode().build().toUriString();
        }

        final String requestId = generateRandomString(32);
        requestsById.put(requestId, Collections.unmodifiableMap(new HashMap<>(params)));

        modelMap.addAttribute("client", client);
        modelMap.addAttribute("reqid", requestId);
        modelMap.addAttribute("scope", reqScope);

        final Map<String, String> traceParams = new HashMap<>();
        final TextMap textMap = new TextMapAdapter(traceParams);
        tracer.inject(span.context(), Format.Builtin.TEXT_MAP, textMap);
        logger.info("Trace params: {}", traceParams);
        modelMap.addAttribute("traceParams", traceParams);

        span.finish();

        return "approve";
    }

    @PostMapping(path = "/approve")
    public String approve(@RequestParam final Map<String, String> params,
                          final ModelMap modelMap
                         ) {
        logger.info("Received POST /approve, parameters: {}", params);
        final SpanContext parentSpan = tracer.extract(Format.Builtin.TEXT_MAP, new TextMapAdapter(params));
        Tracer.SpanBuilder spanBuilder;
        try {
            if (parentSpan == null) {
                spanBuilder = tracer.buildSpan("approve");
            } else {
                spanBuilder = tracer.buildSpan("approve").asChildOf(parentSpan);
            }
        } catch (final IllegalArgumentException e) {
            spanBuilder = tracer.buildSpan("approve");
        }

        final Map<String, String> query = Optional.ofNullable(params.get("reqid"))
                                                  .map(requestsById::remove)
                                                  .orElse(null);
        final Span span = spanBuilder.start();
        span.log("Received POST /approve");
        span.log(params);
        span.log(query);

        if (query == null) {
            modelMap.addAttribute("error", "No matching authorization request");
            return "error";
        }

        logger.info("Authorization request was: {}", query);

        if (params.containsKey("approve")) {
            span.setTag("user_approve_response", true);
            final String responseType = query.get("response_type");
            if (Objects.equals("code", responseType)) {
                final String code = generateRandomString(8);
                final Set<String> scope = params.keySet().stream()
                                                .filter(s -> s.startsWith("scope_"))
                                                .map(s -> s.substring("scope_".length()))
                                                .collect(toSet());
                span.setTag("user_approved_scope", scope.toString());
                final OauthClient client = clientsById.get(query.get("client_id"));

                final Set<String> cScope = Stream.of(client.getScope())
                                                 .filter(StringUtils::hasText)
                                                 .flatMap(s -> Arrays.stream(s.split(" ")))
                                                 .collect(toSet());

                if (!cScope.containsAll(scope)) {
                    span.setTag("decision", "Denied, invalid scope " + scope);
                    final UriComponentsBuilder redirectBuilder =
                        UriComponentsBuilder.fromUriString(query.get("redirect_uri"));
                    redirectBuilder.queryParam("error", "invalid_scope");
                    addSpanDataAndInject(parentSpan, redirectBuilder::queryParam);
                    span.finish();
                    return "redirect:" + redirectBuilder.encode().build().toUriString();
                }
                span.setTag("decision", "Approved");

                final Map<String, Object> codeMap = new HashMap<>();
                codeMap.put("authorizationEndpointRequest", Collections.unmodifiableMap(query));
                codeMap.put("scope", Collections.unmodifiableSet(scope));
                codeMap.put("user", params.get("user"));
                codes.put(code, Collections.unmodifiableMap(codeMap));

                final UriComponentsBuilder redirectBuilder =
                    UriComponentsBuilder.fromUriString(query.get("redirect_uri"));
                redirectBuilder.queryParam("code", code);
                redirectBuilder.queryParam("state", query.get("state"));
                addSpanDataAndInject(parentSpan, redirectBuilder::queryParam);
                span.finish();
                return "redirect:" + redirectBuilder.encode().build().toUriString();
            } else {
                span.setTag("decision", "Denied, invalid response type " + responseType);
                // we got a response type we don't understand
                final UriComponentsBuilder redirectBuilder =
                    UriComponentsBuilder.fromUriString(query.get("redirect_uri"));
                redirectBuilder.queryParam("error", "unsupported_response_type");
                addSpanDataAndInject(parentSpan, redirectBuilder::queryParam);
                span.finish();
                return "redirect:" + redirectBuilder.encode().build().toUriString();
            }
        } else {
            span.setTag("user_approve_response", false);
            span.setTag("decision", "Denied by user");

            // user denied access
            final UriComponentsBuilder redirectBuilder =
                UriComponentsBuilder.fromUriString(query.get("redirect_uri"));
            redirectBuilder.queryParam("error", "access_denied");
            addSpanDataAndInject(parentSpan, redirectBuilder::queryParam);
            span.finish();
            return "redirect:" + redirectBuilder.encode().build().toUriString();
        }
    }

    private void addSpanDataAndInject(final SpanContext spanContext, final BiConsumer<? super String, ? super String> consumer) {
        final Map<String, String> traceParams = new HashMap<>();
        final TextMap textMap = new TextMapAdapter(traceParams);
        tracer.inject(spanContext, Format.Builtin.TEXT_MAP, textMap);
        traceParams.forEach(consumer);
    }

    @PostMapping(path = "/token", produces = MediaType.APPLICATION_JSON_UTF8_VALUE)
    public ResponseEntity<Object> token(@RequestHeader("Authorization") final Optional<String> auth,
                                        @RequestParam final Map<String, String> params
                                       ) {
        logger.info("Received POST /token");
        final SpanContext parentSpan = tracer.extract(Format.Builtin.TEXT_MAP, new TextMapAdapter(params));

        Tracer.SpanBuilder spanBuilder;
        try {
            if (parentSpan == null) {
                spanBuilder = tracer.buildSpan("token");
            } else {
                spanBuilder = tracer.buildSpan("token").asChildOf(parentSpan);
            }
        } catch (final IllegalArgumentException e) {
            spanBuilder = tracer.buildSpan("token");
        }
        final Span span = spanBuilder.start();
        span.log("Received POST /token");

        final String clientId;
        final String clientSecret;
        if (auth.isPresent()) {
            final String[] authCredentials =
                new String(decoder.decode(auth.get().substring("basic ".length())), StandardCharsets.UTF_8)
                    .split(":");
            clientId = authCredentials[0];
            clientSecret = authCredentials[1];
        } else if (params.containsKey("client_id")) {
            clientId = params.get("client_id");
            clientSecret = params.get("client_secret");
        } else {
            logger.error("No client ID in Authorization header or request parameter");
            span.log("Unauthorized request");
            span.finish();
            final ResponseEntity.BodyBuilder responseBuilder = ResponseEntity.status(HttpStatus.UNAUTHORIZED);
            addSpanDataAndInject(parentSpan, responseBuilder::header);
            return responseBuilder.body(Collections.singletonMap("error", "invalid_client"));
        }

        final OauthClient client = clientsById.get(clientId);

        if (client == null) {
            logger.error("Client ID is invalid");
            span.log("Client is invalid");
            span.finish();
            final ResponseEntity.BodyBuilder responseBuilder = ResponseEntity.status(HttpStatus.UNAUTHORIZED);
            addSpanDataAndInject(parentSpan, responseBuilder::header);
            return responseBuilder.body(Collections.singletonMap("error", "invalid_client"));
        }

        if (!Objects.equals(clientSecret, client.getClientSecret())) {
            logger.error("Client Secret is invalid");
            span.log("Client is invalid");
            span.finish();
            final ResponseEntity.BodyBuilder responseBuilder = ResponseEntity.status(HttpStatus.UNAUTHORIZED);
            addSpanDataAndInject(parentSpan, responseBuilder::header);
            return responseBuilder.body(Collections.singletonMap("error", "invalid_client"));
        }
        span.setTag("grantType", params.getOrDefault("grant_type", "null"));

        if (Objects.equals("authorization_code", params.get("grant_type"))) {
            final Map<String, Object> code = Optional.ofNullable(params.get("code"))
                                                     .map(codes::remove)
                                                     .orElse(null);
            if (code != null) {
                @SuppressWarnings("unchecked")
                final Map<String, String> authRequest =
                    (Map<String, String>) code.get("authorizationEndpointRequest");
                final Object expectedClientId = Optional.ofNullable(authRequest)
                                                        .map(q -> q.get("client_id"))
                                                        .orElse(null);
                if (Objects.equals(clientId, expectedClientId)) {
                    final String expectedRedirectUri = Optional.ofNullable(authRequest)
                                                               .map(q -> q.get("redirect_uri"))
                                                               .orElse(null);
                    final String actualRedirectUri = params.get("redirect_uri");
                    if (Objects.equals(expectedRedirectUri, actualRedirectUri)) {
                        final String accessToken = generateRandomString(32);
                        final String refreshToken = generateRandomString(64);

                        @SuppressWarnings("unchecked")
                        final String cscope = Stream.of(code.get("scope"))
                                                    .filter(Objects::nonNull)
                                                    .flatMap(s -> ((Set<String>) s).stream())
                                                    .collect(Collectors.joining(" "));

                        return generateTokensAndResponse(clientId, accessToken, refreshToken, cscope, span);
                    } else {
                        logger.error("Redirect URI mismatch, expected {} got {}",
                                     expectedRedirectUri, actualRedirectUri
                                    );
                        span.log("Redirect URI is invalid");
                        span.finish();
                        final ResponseEntity.BodyBuilder responseBuilder = ResponseEntity.status(HttpStatus.BAD_REQUEST);
                        addSpanDataAndInject(parentSpan, responseBuilder::header);
                        return responseBuilder.body(Collections.singletonMap("error", "invalid_grant"));
                    }
                } else {
                    logger.error("Client mismatch, expected {} got {}", expectedClientId, clientId);
                    span.log("Client ID mismatch");
                    span.finish();
                    final ResponseEntity.BodyBuilder responseBuilder = ResponseEntity.status(HttpStatus.BAD_REQUEST);
                    addSpanDataAndInject(parentSpan, responseBuilder::header);
                    return responseBuilder.body(Collections.singletonMap("error", "invalid_grant"));
                }
            } else {
                logger.error("Unknown code {}", params.get("code"));
                span.log("Unknown code");
                span.finish();
                final ResponseEntity.BodyBuilder responseBuilder = ResponseEntity.status(HttpStatus.BAD_REQUEST);
                addSpanDataAndInject(parentSpan, responseBuilder::header);
                return responseBuilder.body(Collections.singletonMap("error", "invalid_grant"));
            }
        } else if (Objects.equals("refresh_token", params.get("grant_type"))) {
            final Span rfSpan = tracer.buildSpan("find-refresh-token").asChildOf(span).start();
            final RefreshTokenInfo refreshTokenInfo =
                refreshTokenRepository.findByRefreshToken(params.get("refresh_token"));
            rfSpan.finish();
            if (refreshTokenInfo != null) {
                if (!Objects.equals(clientId, refreshTokenInfo.getClientId())) {
                    span.log("Refresh token compromised, delete");
                    logger.error("Invalid client using a refresh token, expected {} got {}",
                                 clientId, refreshTokenInfo.getClientId()
                                );
                    final Span rdSpan = tracer.buildSpan("delete-refresh-token").asChildOf(span).start();
                    refreshTokenRepository.delete(refreshTokenInfo);
                    rdSpan.finish();
                    span.finish();
                    final ResponseEntity.BodyBuilder responseBuilder = ResponseEntity.status(HttpStatus.BAD_REQUEST);
                    addSpanDataAndInject(parentSpan, responseBuilder::header);
                    return responseBuilder.build();
                }
                logger.info("Found matching refresh token: {}", refreshTokenInfo.getRefreshToken());

                final String accessToken = generateRandomString(32);
                final String refreshToken = generateRandomString(64);

                final String cscope = refreshTokenInfo.getScope();
                final Span rdSpan = tracer.buildSpan("find-refresh-token").asChildOf(span).start();
                refreshTokenRepository.delete(refreshTokenInfo);
                rdSpan.finish();
                return generateTokensAndResponse(clientId, accessToken, refreshToken, cscope, span);
            } else {
                logger.error("No matching token was found");
                span.log("Invalid token");
                span.finish();
                final ResponseEntity.BodyBuilder responseBuilder = ResponseEntity.status(HttpStatus.UNAUTHORIZED);
                addSpanDataAndInject(parentSpan, responseBuilder::header);
                return responseBuilder.build();
            }
        } else {
            logger.error("Unknown grant type {}", params.get("grant_type"));
            span.log("Invalid grant type");
            span.finish();
            final ResponseEntity.BodyBuilder responseBuilder = ResponseEntity.status(HttpStatus.BAD_REQUEST);
            addSpanDataAndInject(parentSpan, responseBuilder::header);
            return responseBuilder.body(Collections.singletonMap("error", "invalid_grant_type"));
        }
    }

    private ResponseEntity<Object> generateTokensAndResponse(final String clientId,
                                                             final String accessToken,
                                                             final String refreshToken,
                                                             final String cscope,
                                                             final Span span
                                                            ) {
        final Instant now = Instant.now();
        final Tracer.SpanBuilder aSpanBuilder = tracer.buildSpan("save-access-token").asChildOf(span);
        aSpanBuilder.withTag("clientId", clientId);
        aSpanBuilder.withTag("scope", cscope);
        final Span aSpan = aSpanBuilder.start();
        accessTokenRepository.save(
            new AccessTokenInfo(
                accessToken,
                clientId,
                StringUtils.hasText(cscope) ? cscope : null,
                now,
                now.plus(tokenMaxAge)
            )
                                  );
        aSpan.finish();
        final Tracer.SpanBuilder rSpanBuilder = tracer.buildSpan("save-refresh-token").asChildOf(span);
        rSpanBuilder.withTag("clientId", clientId);
        rSpanBuilder.withTag("scope", cscope);
        final Span rSpan = rSpanBuilder.start();
        refreshTokenRepository.save(
            new RefreshTokenInfo(
                refreshToken,
                clientId,
                StringUtils.hasText(cscope) ? cscope : null,
                Instant.now()
            )
                                   );
        rSpan.finish();
        logger.info("Issued access token {} with scope {}", accessToken, cscope);

        final Map<String, Object> tokenResponse = new HashMap<>();
        tokenResponse.put("scope", StringUtils.hasText(cscope) ? cscope : null);
        tokenResponse.put("access_token", accessToken);
        tokenResponse.put("expires_in", tokenMaxAge.getSeconds());
        tokenResponse.put("token_type", "Bearer");
        tokenResponse.put("refresh_token", refreshToken);

        span.finish();

        return ResponseEntity.ok(tokenResponse);
    }

    private String generateRandomString(final int bytesLength) {
        final byte[] bytes = new byte[bytesLength];
        secureRandom.nextBytes(bytes);
        return new String(encoder.encode(bytes), StandardCharsets.UTF_8);
    }
}
