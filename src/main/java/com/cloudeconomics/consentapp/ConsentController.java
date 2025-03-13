package com.cloudeconomics.consentapp;

import com.microsoft.aad.msal4j.*;

import io.github.cdimascio.dotenv.Dotenv;
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

    private static final Dotenv dotenv = Dotenv.configure().ignoreIfMissing().load();

    private final static String CLIENT_ID = dotenv.get("AZURE_CLIENT_ID") != null ? dotenv.get("AZURE_CLIENT_ID")
            : System.getenv("AZURE_CLIENT_ID");

    private final static String CLIENT_SECRET = dotenv.get("AZURE_CLIENT_SECRET") != null
            ? dotenv.get("AZURE_CLIENT_SECRET")
            : System.getenv("AZURE_CLIENT_SECRET");

    private final static String REDIRECT_URI = dotenv.get("REDIRECT_URI") != null ? dotenv.get("REDIRECT_URI")
            : System.getenv("REDIRECT_URI") != null ? System.getenv("REDIRECT_URI") : "http://localhost:8080/redirect";

    private final static String AUTHORITY = "https://login.microsoftonline.com/common";

    @GetMapping("/")
    public ModelAndView home() {
        ModelAndView mav = new ModelAndView("home");
        try {
            ConfidentialClientApplication app = ConfidentialClientApplication.builder(
                    CLIENT_ID,
                    ClientCredentialFactory.createFromSecret(CLIENT_SECRET))
                    .authority(AUTHORITY)
                    .build();

            // Request only one resource scope
            Set<String> scopes = Collections.singleton(
                    "https://management.azure.com/user_impersonation");

            AuthorizationRequestUrlParameters parameters = AuthorizationRequestUrlParameters
                    .builder(REDIRECT_URI, scopes)
                    .prompt(Prompt.CONSENT)
                    .responseMode(ResponseMode.QUERY)
                    .build();

            String authUrl = app.getAuthorizationRequestUrl(parameters).toString();
            System.out.println("Auth URL: " + authUrl);
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
    boolean rolesAssigned = false;  // Define variable outside try block
    String tenantId = null;         // Define variable outside try block

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

        // Request only one resource scope
        Set<String> scopes = Collections.singleton(
                "https://management.azure.com/user_impersonation");

        AuthorizationCodeParameters authCodeParams = AuthorizationCodeParameters
                .builder(code, new URI(REDIRECT_URI))
                .scopes(scopes) // Only one resource scope
                .build();

        CompletableFuture<IAuthenticationResult> future = app.acquireToken(authCodeParams);
        IAuthenticationResult result = future.join();

        // Extract tenant ID
        tenantId = extractTenantIdFromToken(result.accessToken());
        
        // Assign Azure roles to the service principal
        rolesAssigned = assignRolesToServicePrincipal(result.accessToken());

        // Redirect to thank you page
        mav.setViewName("redirect:/thankyou");
        mav.addObject("rolesAssigned", rolesAssigned);
        mav.addObject("tenantId", tenantId);
        return mav;
    } catch (Exception e) {
        System.err.println("Error processing authorization code: " + e.getMessage());
        mav.setViewName("redirect:/thankyou");
        mav.addObject("rolesAssigned", rolesAssigned);  // Now it's defined
        mav.addObject("tenantId", tenantId);           // Now it's defined
        return mav;
    }
}

    @GetMapping("/thankyou")
    public ModelAndView thankYou(@RequestParam(required = false) Boolean rolesAssigned,
            @RequestParam(required = false) String tenantId) {

        ModelAndView mav = new ModelAndView("thankyou");
        mav.addObject("rolesAssigned", rolesAssigned != null && rolesAssigned);
        mav.addObject("tenantId", tenantId);
        // Generate a suggested storage account name
        String suggestedStorageName = "ateacloudeconomics-"
                + (tenantId != null ? tenantId.substring(0, Math.min(8, tenantId.length())) : "customer");
        mav.addObject("suggestedStorageName", suggestedStorageName);
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
                    + "\"appRoleAssignmentRequired\": true," // Requires admin to assign the app
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
                    System.err.println("Failed to configure enterprise app: Status: " + response.code() + ", Response: "
                            + responseBody);
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
            String rootManagementGroupScope = "/providers/Microsoft.Management/managementGroups/"
                    + rootManagementGroupId;
    
            // Step 3: Get the service principal ID with retries (consent might take time to propagate)
            String servicePrincipalId = null;
            for (int i = 0; i < 5 && servicePrincipalId == null; i++) {
                servicePrincipalId = getServicePrincipalId(client, accessToken, tenantId);
                if (servicePrincipalId == null && i < 4) {
                    System.out.println("Service principal not found, waiting to retry... (" + (i+1) + "/5)");
                    Thread.sleep(2000); // Wait 2 seconds between retries
                }
            }
            
            if (servicePrincipalId == null) {
                System.err.println("Could not find service principal ID after multiple attempts");
                return false;
            }
    
            // Step 4: Configure the enterprise app (hide from users, disable sign-in)
            configureEnterpriseApp(accessToken, tenantId, servicePrincipalId);
    
            // Step 5: Assign roles - using the USER'S access token
            boolean success = true;
            success &= assignRole(client, accessToken, "Reader", servicePrincipalId, rootManagementGroupScope);
            success &= assignRole(client, accessToken, "Cost Management Contributor", servicePrincipalId,
                    rootManagementGroupScope);
            success &= assignRole(client, accessToken, "Reservation Reader", servicePrincipalId,
                    "/providers/Microsoft.Capacity");
    
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
            if (parts.length < 2)
                return null;

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
            // Query the service principal in the user's tenant based on the app ID
            String url = "https://graph.microsoft.com/v1.0/servicePrincipals?$filter=appId eq '" + CLIENT_ID + "'";
            
            // First we need a Graph token using the user's credentials
            String graphToken = getGraphToken(accessToken, tenantId);
            if (graphToken == null) {
                System.err.println("Could not get Graph API token");
                return null;
            }
            
            Request request = new Request.Builder()
                .url(url)
                .get()
                .addHeader("Authorization", "Bearer " + graphToken)
                .build();
                
            try (Response response = client.newCall(request).execute()) {
                if (response.isSuccessful() && response.body() != null) {
                    String responseBody = response.body().string();
                    JSONObject json = new JSONObject(responseBody);
                    JSONArray values = json.getJSONArray("value");
                    
                    if (values.length() > 0) {
                        // Get the first matching service principal
                        JSONObject servicePrincipal = values.getJSONObject(0);
                        return servicePrincipal.getString("id");
                    }
                } else {
                    String responseBody = response.body() != null ? response.body().string() : "";
                    System.err.println("Failed to get service principal: Status: " + response.code() + 
                        ", Response: " + responseBody);
                }
            }
            
            // Fallback - not ideal but might work in some cases
            return CLIENT_ID;
        } catch (Exception e) {
            System.err.println("Error getting service principal: " + e.getMessage());
            e.printStackTrace();
            return null;
        }
    }
    
    private boolean assignRole(OkHttpClient client, String accessToken, String roleName, String principalId,
            String scope) {
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
                    System.err.println("Failed to assign role: " + roleName + ", Status: " + response.code()
                            + ", Response: " + responseBody);
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
            String url = "https://management.azure.com" + scope
                    + "/providers/Microsoft.Authorization/roleDefinitions?$filter=roleName%20eq%20'"
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