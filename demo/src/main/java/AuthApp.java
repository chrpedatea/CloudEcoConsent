import com.microsoft.aad.msal4j.*;

import java.net.URI;
import java.util.Collections;
import java.util.Set;
import java.util.concurrent.CompletableFuture;

public class AuthApp {

        private final static String CLIENT_ID = System.getenv("AZURE_CLIENT_ID");
        private final static String CLIENT_SECRET = System.getenv("AZURE_CLIENT_SECRET");
        private final static String AUTHORITY = "https://login.microsoftonline.com/common";

        public static void main(String[] args) throws Exception {
                ConfidentialClientApplication app = ConfidentialClientApplication.builder(
                                CLIENT_ID,
                                ClientCredentialFactory.createFromSecret(CLIENT_SECRET))
                                .authority(AUTHORITY)
                                .build();

                // Step 1: Get Authorization URL
                AuthorizationRequestUrlParameters parameters = AuthorizationRequestUrlParameters
                                .builder("http://localhost:8080/redirect",
                                                Collections.singleton("https://graph.microsoft.com/.default"))
                                .build();

                String authUrl = app.getAuthorizationRequestUrl(parameters).toString();
                System.out.println("Please go to this URL and grant consent: " + authUrl);

                // Step 2: Simulate receiving the authorization code
                // In a real application, you would set up a web server to handle the redirect
                System.out.println("Enter the authorization code:");
                String authCode = new java.util.Scanner(System.in).nextLine();

                // Step 3: Exchange authorization code for access token
                AuthorizationCodeParameters authCodeParams = AuthorizationCodeParameters
                                .builder(authCode, new URI("http://localhost:8080/redirect"))
                                .build();

                CompletableFuture<IAuthenticationResult> future = app.acquireToken(authCodeParams);
                IAuthenticationResult result = future.join();

                System.out.println("Access Token: " + result.accessToken());
        }
}