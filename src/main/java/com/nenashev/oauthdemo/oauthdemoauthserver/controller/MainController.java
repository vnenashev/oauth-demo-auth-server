package com.nenashev.oauthdemo.oauthdemoauthserver.controller;

import com.nenashev.oauthdemo.oauthdemoauthserver.config.OauthConfig;
import com.nenashev.oauthdemo.oauthdemoauthserver.db.AccessTokenRepository;
import com.nenashev.oauthdemo.oauthdemoauthserver.model.AccessTokenInfo;
import com.nenashev.oauthdemo.oauthdemoauthserver.model.OauthClient;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Function;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
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
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.util.UriComponentsBuilder;

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

    private final Map<String, OauthClient> clientsById;

    private final Map<String, Map<String, String>> requestsById = new ConcurrentHashMap<>();

    private final Map<String, Map<String, Object>> codes = new ConcurrentHashMap<>();

    public MainController(final OauthConfig oauthConfig,
                          final SecureRandom secureRandom,
                          final AccessTokenRepository accessTokenRepository) {
        this.oauthConfig = oauthConfig;
        this.secureRandom = secureRandom;
        this.accessTokenRepository = accessTokenRepository;
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
    public String authorize(final @RequestParam Map<String, String> params,
                            final ModelMap modelMap) {
        logger.info("Received GET /authorize with parameters: {}", params);

        final String reqClientId = params.get("client_id");
        final OauthClient client = clientsById.get(reqClientId);

        if (client == null) {
            logger.error("Unknown client {}", reqClientId);
            modelMap.addAttribute("error", "Unknown client");
            return "error";
        }

        final String reqRedirectUri = params.get("redirect_uri");
        if (!client.getRedirectUris().contains(reqRedirectUri)) {
            logger.error("Mismatched redirect URI, expected {}, got {}", client.getRedirectUris(), reqRedirectUri);
            modelMap.addAttribute("error", "Invalid redirect URI");
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
            return "redirect:" + redirectBuilder.encode().build().toUriString();
        }

        final byte[] requestIdBytes = new byte[32];
        secureRandom.nextBytes(requestIdBytes);
        final String requestId = new String(encoder.encode(requestIdBytes), StandardCharsets.UTF_8);
        requestsById.put(requestId, Collections.unmodifiableMap(new HashMap<>(params)));

        modelMap.addAttribute("client", client);
        modelMap.addAttribute("reqid", requestId);
        modelMap.addAttribute("scope", reqScope);

        return "approve";
    }

    @PostMapping(path = "/approve")
    public String approve(final @RequestParam Map<String, String> params,
                          final ModelMap modelMap) {
        logger.info("Received POST /approve, parameters: {}", params);

        final Map<String, String> query = Optional.ofNullable(params.get("reqid"))
            .map(requestsById::remove)
            .orElse(null);

        if (query == null) {
            modelMap.addAttribute("error", "No matching authorization request");
            return "error";
        }

        logger.info("Authorization request was: {}", query);

        if (params.containsKey("approve")) {
            if (Objects.equals("code", query.get("response_type"))) {
                final byte[] bcode = new byte[8];
                secureRandom.nextBytes(bcode);
                final String code = new String(encoder.encode(bcode), StandardCharsets.UTF_8);
                final Set<String> scope = params.keySet().stream()
                    .filter(s -> s.startsWith("scope_"))
                    .map(s -> s.substring("scope_".length()))
                    .collect(toSet());
                final OauthClient client = clientsById.get(query.get("client_id"));

                final Set<String> cScope = Stream.of(client.getScope())
                    .filter(StringUtils::hasText)
                    .flatMap(s -> Arrays.stream(s.split(" ")))
                    .collect(toSet());

                if (!cScope.containsAll(scope)) {
                    final UriComponentsBuilder redirectBuilder =
                        UriComponentsBuilder.fromUriString(query.get("redirect_uri"));
                    redirectBuilder.queryParam("error", "invalid_scope");
                    return "redirect:" + redirectBuilder.encode().build().toUriString();
                }

                final Map<String, Object> codeMap = new HashMap<>();
                codeMap.put("authorizationEndpointRequest", Collections.unmodifiableMap(query));
                codeMap.put("scope", Collections.unmodifiableSet(scope));
                codeMap.put("user", params.get("user"));
                codes.put(code, Collections.unmodifiableMap(codeMap));

                final UriComponentsBuilder redirectBuilder =
                    UriComponentsBuilder.fromUriString(query.get("redirect_uri"));
                redirectBuilder.queryParam("code", code);
                redirectBuilder.queryParam("state", query.get("state"));
                return "redirect:" + redirectBuilder.encode().build().toUriString();
            } else {
                // we got a response type we don't understand
                final UriComponentsBuilder redirectBuilder =
                    UriComponentsBuilder.fromUriString(query.get("redirect_uri"));
                redirectBuilder.queryParam("error", "unsupported_response_type");
                return "redirect:" + redirectBuilder.encode().build().toUriString();
            }
        } else {
            // user denied access
            final UriComponentsBuilder redirectBuilder =
                UriComponentsBuilder.fromUriString(query.get("redirect_uri"));
            redirectBuilder.queryParam("error", "access_denied");
            return "redirect:" + redirectBuilder.encode().build().toUriString();
        }
    }

    @PostMapping(path = "/token", produces = MediaType.APPLICATION_JSON_UTF8_VALUE)
    @ResponseBody
    public Object token(final @RequestHeader("Authorization") Optional<String> auth,
                        final @RequestParam Map<String, String> params) {
        logger.info("Received POST /token, authorization: {}, parameters: {}", auth, params);

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
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body(Collections.singletonMap("error", "invalid_client"));
        }

        final OauthClient client = clientsById.get(clientId);

        if (client == null) {
            logger.error("Unknown client {}", clientId);
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body(Collections.singletonMap("error", "invalid_client"));
        }

        if (!Objects.equals(clientSecret, client.getClientSecret())) {
            logger.error("Mismatched client secret expected {} got {}", client.getClientSecret(), clientSecret);
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body(Collections.singletonMap("error", "invalid_client"));
        }

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
                        final byte[] at = new byte[32];
                        secureRandom.nextBytes(at);
                        final String accessToken = new String(encoder.encode(at), StandardCharsets.UTF_8);
                        @SuppressWarnings("unchecked")
                        final String cscope = Stream.of(code.get("scope"))
                            .filter(Objects::nonNull)
                            .flatMap(s -> ((Set<String>) s).stream())
                            .collect(Collectors.joining(" "));

                        accessTokenRepository.save(
                            new AccessTokenInfo(accessToken, clientId, StringUtils.hasText(cscope) ? cscope : null)
                        );

                        logger.info("Issuing access token {} with scope {}", accessToken, cscope);

                        final Map<String, String> tokenResponse = new HashMap<>();
                        tokenResponse.put("scope", StringUtils.hasText(cscope) ? cscope : null);
                        tokenResponse.put("access_token", accessToken);
                        tokenResponse.put("token_type", "Bearer");

                        return ResponseEntity.ok(tokenResponse);
                    } else {
                        logger.error("Redirect URI mismatch, expected {} got {}",
                            expectedRedirectUri, actualRedirectUri);
                        return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                            .body(Collections.singletonMap("error", "invalid_grant"));
                    }
                } else {
                    logger.error("Client mismatch, expected {} got {}", expectedClientId, clientId);
                    return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                        .body(Collections.singletonMap("error", "invalid_grant"));
                }
            } else {
                logger.error("Unknown code {}", params.get("code"));
                return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(Collections.singletonMap("error", "invalid_grant"));
            }
        } else {
            logger.error("Unknown grant type {}", params.get("grant_type"));
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                .body(Collections.singletonMap("error", "invalid_grant_type"));
        }
    }
}
