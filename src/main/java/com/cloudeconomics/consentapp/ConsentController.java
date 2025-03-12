package com.cloudeconomics.consentapp;

import com.microsoft.aad.msal4j.*;
import okhttp3.*;
import org.json.JSONArray;
import org.json.JSONObject;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.ModelAndView;

import java.net.URI;
import java.util.*;
import java.util.concurrent.CompletableFuture;

@Controller
public class ConsentController {

    private final static String CLIENT_ID = System.getenv("AZURE_CLIENT_ID");
    private final static String CLIENT_SECRET = System.getenv("AZURE_CLIENT_SECRET");
    private final static String AUTHORITY = "https://login.microsoftonline.com/common";
    private final static String REDIRECT_URI = System.getenv("REDIRECT_URI") != null ? 
            System.getenv("REDIRECT_URI") : "http://localhost:8080/redirect";

    @GetMapping("/")
    public ModelAndView home() {
        ModelAndView mav = new ModelAndView("home");
        try {
            ConfidentialClientApplication app = ConfidentialClientApplication.builder(
                    CLIENT_ID,
                    ClientCredentialFactory.createFromSecret(CLIENT_SECRET))
                    .authority(AUTHORITY)
                    .build();

            // Scope for Azure management
            Set<String> scopes = new HashSet<>(Arrays.asList(
                "https://management.azure.com/user_impersonation",
                "https://management.core.windows.net/user_impersonation"
            ));

            AuthorizationRequestUrlParameters parameters =
                    AuthorizationRequestUrlParameters.builder(REDIRECT_URI, scopes)
                            .prompt(Prompt.CONSENT)  // Force consent dialog
                            .responseMode(ResponseMode.QUERY)
                            .build();

            String authUrl = app.getAuthorizationRequestUrl(parameters).toString();
            System.out.println("Auth URL: " + authUrl); // For debugging
            mav.addObject("authUrl", authUrl);
        } catch (Exception e) {
            mav.addObject("error", "Error generating consent URL: " + e.getMessage());
        }
        return mav;
    }

    @GetMapping("/redirect")
    public ModelAndView handleRedirect(@RequestParam(value = "code", required = false) String code,
                                      @RequestParam(value = "error", required = false) String error) {
        ModelAndView mav = new ModelAndView();
        
        if (error != null) {
            mav.setViewName("result");
            mav.addObject("status", "Error");
            mav.addObject("message", "Consent failed: " + error);
            return mav;
        }
        
        if (code == null) {
            mav.setViewName("result");
            mav.addObject("status", "Error");
            mav.addObject("message", "No authorization code received");
            return mav;
        }
        
        try {
            ConfidentialClientApplication app = ConfidentialClientApplication.builder(
                    CLIENT_ID,
                    ClientCredentialFactory.createFromSecret(CLIENT_SECRET))
                    .authority(AUTHORITY)
                    .build();

            AuthorizationCodeParameters authCodeParams =
                    AuthorizationCodeParameters.builder(code, new URI(REDIRECT_URI))
                            .build();

            CompletableFuture<IAuthenticationResult> future = app.acquireToken(authCodeParams);
            IAuthenticationResult result = future.join();
            
            // Assign Azure roles to the service principal
            boolean rolesAssigned = assignRolesToServicePrincipal(result.accessToken());
            
            // Redirect to thank you page
            mav.setViewName("redirect:/thankyou");
            return mav;
        } catch (Exception e) {
            mav.setViewName("result");
            mav.addObject("status", "Error");
            mav.addObject("message", "Error processing authorization code: " + e.getMessage());
            return mav;
        }
    }
    
    @GetMapping("/thankyou")
    public ModelAndView thankYou() {
        ModelAndView mav = new ModelAndView("thankyou");
        return mav;
    }

    private boolean configureEnterpriseApp(String accessToken, String tenantId, String servicePrincipalId) {
    try {
        OkHttpClient client = new OkHttpClient();
        
        // Get an access token for Microsoft Graph
        String graphToken = getGraphToken(accessToken, tenantId);
        if (graphToken == null) {
            System.err.println("Could not get Graph API token");
            return false;
        }
        
        // Configure the enterprise app (service principal) to be hidden from users
        String url = "https://graph.microsoft.com/v1.0/servicePrincipals/" + servicePrincipalId;
        
        String requestBody = "{"
            + "\"accountEnabled\": true,"
            + "\"appRoleAssignmentRequired\": true,"  // Requires admin to assign the app
            + "\"disabledByMicrosoftStatus\": null,"
            + "\"displayName\": \"Cloud Economics\","
            + "\"homepage\": \"https://ateacloudeconomics.azurewebsites.net\","
            + "\"tags\": [\"WindowsAzureActiveDirectoryIntegratedApp\", \"HideApp\"],"
            + "\"notificationEmailAddresses\": [],"
            + "\"publisherName\": \"Cloud Economics\","
            + "\"servicePrincipalType\": \"Application\","
            + "\"preferredSingleSignOnMode\": null,"
            + "\"visibility\": null"
            + "}";
        
        RequestBody body = RequestBody.create(MediaType.parse("application/json"), requestBody);
        Request request = new Request.Builder()
            .url(url)
            .patch(body)
            .addHeader("Authorization", "Bearer " + graphToken)
            .addHeader("Content-Type", "application/json")
            .build();
        
        try (Response response = client.newCall(request).execute()) {
            if (response.isSuccessful()) {
                System.out.println("Successfully configured enterprise app visibility");
                return true;
            } else {
                String responseBody = response.body() != null ? response.body().string() : "";
                System.err.println("Failed to configure enterprise app: Status: " + response.code() + ", Response: " + responseBody);
                return false;
            }
        }
    } catch (Exception e) {
        System.err.println("Error configuring enterprise app: " + e.getMessage());
        return false;
    }
}

    private String getGraphToken(String accessToken, String tenantId) {
    try {
        // Use OBO (On-Behalf-Of) flow to get a token for Graph API
        ConfidentialClientApplication app = ConfidentialClientApplication.builder(
                CLIENT_ID,
                ClientCredentialFactory.createFromSecret(CLIENT_SECRET))
                .authority("https://login.microsoftonline.com/" + tenantId)
                .build();
        
        // Define the scopes required for Microsoft Graph
        Set<String> scopes = Collections.singleton("https://graph.microsoft.com/.default");
        
        // Build user assertion from the original access token
        UserAssertion userAssertion = new UserAssertion(accessToken);
        
        // Get token for Microsoft Graph API
        OnBehalfOfParameters parameters = OnBehalfOfParameters
                .builder(scopes, userAssertion)
                .build();
        
        CompletableFuture<IAuthenticationResult> future = app.acquireToken(parameters);
        IAuthenticationResult result = future.join();
        
        return result.accessToken();
    } catch (Exception e) {
        System.err.println("Error getting Graph token: " + e.getMessage());
        return null;
    }
}
    
    private boolean assignRolesToServicePrincipal(String accessToken) {
    try {
        OkHttpClient client = new OkHttpClient();
        
        // Step 1: Get tenant details
        String tenantId = extractTenantIdFromToken(accessToken);
        if (tenantId == null) {
            System.err.println("Could not extract tenant ID from token");
            return false;
        }
        
        // Step 2: Get the root management group ID (usually matches tenant ID)
        String rootManagementGroupId = tenantId;
        String rootManagementGroupScope = "/providers/Microsoft.Management/managementGroups/" + rootManagementGroupId;
        
        // Step 3: Get the service principal ID (our app ID)
        String servicePrincipalId = getServicePrincipalId(client, accessToken, tenantId);
        if (servicePrincipalId == null) {
            System.err.println("Could not find service principal ID");
            return false;
        }
        
        // Step 4: Configure the enterprise app (hide from users, disable sign-in)
        configureEnterpriseApp(accessToken, tenantId, servicePrincipalId);
        
        // Step 5: Assign roles
        boolean success = true;
        success &= assignRole(client, accessToken, "Reader", servicePrincipalId, rootManagementGroupScope);
        success &= assignRole(client, accessToken, "Cost Management Contributor", servicePrincipalId, rootManagementGroupScope);
        success &= assignRole(client, accessToken, "Reservation Reader", servicePrincipalId, "/providers/Microsoft.Capacity");
        
        return success;
    } catch (Exception e) {
        System.err.println("Error assigning roles: " + e.getMessage());
        e.printStackTrace();
        return false;
    }
}
    
    private String extractTenantIdFromToken(String accessToken) {
        try {
            // Access token is in format: header.payload.signature
            String[] parts = accessToken.split("\\.");
            if (parts.length < 2) return null;
            
            // Decode the payload
            String payload = new String(Base64.getUrlDecoder().decode(parts[1]));
            JSONObject payloadJson = new JSONObject(payload);
            
            // Extract tenant ID from the token claims
            return payloadJson.getString("tid"); // 'tid' is the tenant ID claim
        } catch (Exception e) {
            System.err.println("Error extracting tenant ID: " + e.getMessage());
            return null;
        }
    }

    private String getServicePrincipalId(OkHttpClient client, String accessToken, String tenantId) {
        try {
            // This is the same as the application's client ID for enterprise apps
            return CLIENT_ID;
        } catch (Exception e) {
            System.err.println("Error getting service principal: " + e.getMessage());
            return null;
        }
    }

    private boolean assignRole(OkHttpClient client, String accessToken, String roleName, String principalId, String scope) {
        try {
            // Step 1: Get role definition ID
            String roleDefinitionId = getRoleDefinitionId(client, accessToken, roleName, scope);
            if (roleDefinitionId == null) {
                System.err.println("Could not find role definition ID for: " + roleName);
                return false;
            }
            
            // Step 2: Create a unique name for the role assignment
            String roleAssignmentName = UUID.randomUUID().toString();
            
            // Step 3: Create role assignment
            String url = "https://management.azure.com" + scope + "/providers/Microsoft.Authorization/roleAssignments/" 
                    + roleAssignmentName + "?api-version=2015-07-01";
            
            String requestBody = "{"
                + "\"properties\": {"
                + "\"roleDefinitionId\": \"" + roleDefinitionId + "\","
                + "\"principalId\": \"" + principalId + "\","
                + "\"principalType\": \"ServicePrincipal\""
                + "}"
                + "}";
            
            RequestBody body = RequestBody.create(MediaType.parse("application/json"), requestBody);
            Request request = new Request.Builder()
                .url(url)
                .put(body)
                .addHeader("Authorization", "Bearer " + accessToken)
                .addHeader("Content-Type", "application/json")
                .build();
            
            try (Response response = client.newCall(request).execute()) {
                if (response.isSuccessful()) {
                    System.out.println("Successfully assigned role: " + roleName);
                    return true;
                } else {
                    String responseBody = response.body() != null ? response.body().string() : "";
                    System.err.println("Failed to assign role: " + roleName + ", Status: " + response.code() + ", Response: " + responseBody);
                    return false;
                }
            }
        } catch (Exception e) {
            System.err.println("Error assigning role: " + roleName + ", Error: " + e.getMessage());
            return false;
        }
    }

    private String getRoleDefinitionId(OkHttpClient client, String accessToken, String roleName, String scope) {
        try {
            // Filter role definitions by name
            String url = "https://management.azure.com" + scope + "/providers/Microsoft.Authorization/roleDefinitions?$filter=roleName%20eq%20'" 
                    + roleName.replace(" ", "%20") + "'&api-version=2015-07-01";
            
            Request request = new Request.Builder()
                .url(url)
                .get()
                .addHeader("Authorization", "Bearer " + accessToken)
                .build();
            
            try (Response response = client.newCall(request).execute()) {
                if (response.isSuccessful() && response.body() != null) {
                    String responseBody = response.body().string();
                    JSONObject json = new JSONObject(responseBody);
                    JSONArray values = json.getJSONArray("value");
                    
                    // Find the role definition
                    for (int i = 0; i < values.length(); i++) {
                        JSONObject role = values.getJSONObject(i);
                        JSONObject properties = role.getJSONObject("properties");
                        
                        if (properties.getString("roleName").equalsIgnoreCase(roleName)) {
                            return role.getString("id");
                        }
                    }
                }
            }
            
            return null;
        } catch (Exception e) {
            System.err.println("Error getting role definition: " + e.getMessage());
            return null;
        }
    }
}