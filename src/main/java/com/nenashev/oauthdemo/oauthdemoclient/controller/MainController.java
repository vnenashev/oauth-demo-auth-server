package com.nenashev.oauthdemo.oauthdemoclient.controller;

import com.nenashev.oauthdemo.oauthdemoclient.config.OauthConfig;
import com.nenashev.oauthdemo.oauthdemoclient.model.OauthClient;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.function.Function;
import java.util.stream.Stream;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Controller;
import org.springframework.ui.ModelMap;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.util.UriComponentsBuilder;

import static java.util.stream.Collectors.toMap;
import static java.util.stream.Collectors.toSet;

@Controller
@RequestMapping(path = "/")
public class MainController {

    private final Logger logger = LoggerFactory.getLogger(MainController.class);

    private final Base64.Encoder encoder = Base64.getUrlEncoder().withoutPadding();

    private final OauthConfig oauthConfig;
    private final SecureRandom secureRandom;

    private final Map<String, OauthClient> clientsById;

    private final Map<String, Map<String, String>> requestsById = new HashMap<>();

    public MainController(final OauthConfig oauthConfig,
                          final SecureRandom secureRandom) {
        this.oauthConfig = oauthConfig;
        this.secureRandom = secureRandom;
        this.clientsById = oauthConfig.getClients().stream()
            .collect(toMap(OauthClient::getClientId, Function.identity()));

        logger.info("Initialized main controller with OAuth config: {}", oauthConfig);
    }

    @GetMapping(path = "/")
    public String index(final ModelMap modelMap) {
        modelMap.addAttribute("authServer", oauthConfig);
        return "index";
    }

    @GetMapping(path = "/authorize")
    public String authorize(final @RequestParam Map<String, String> params,
                            final ModelMap modelMap) {
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
        final Set<String> reqScope = StringUtils.hasText(rScope)
            ? Stream.of(rScope.split(" ")).collect(toSet())
            : Collections.emptySet();
        final Set<String> cScope = StringUtils.hasText(client.getScope())
            ? Stream.of(client.getScope().split(" ")).collect(toSet())
            : Collections.emptySet();

        if (!cScope.containsAll(reqScope)) {
            final UriComponentsBuilder redirectBuilder = UriComponentsBuilder.fromUriString(reqRedirectUri);
            redirectBuilder.queryParam("error", "invalid_scope");
            return "redirect:" + redirectBuilder.encode().build().toUriString();
        }

        final byte[] requestIdBytes = new byte[32];
        secureRandom.nextBytes(requestIdBytes);
        final String requestId = new String(encoder.encode(requestIdBytes), StandardCharsets.UTF_8);
        requestsById.put(requestId, new HashMap<>(params));

        modelMap.addAttribute("client", client);
        modelMap.addAttribute("reqid", requestId);
        modelMap.addAttribute("scope",reqScope);

        return "approve";
    }
}
