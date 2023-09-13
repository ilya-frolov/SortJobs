package org.example;

import com.google.api.client.auth.oauth2.Credential;
import com.google.api.client.extensions.java6.auth.oauth2.AuthorizationCodeInstalledApp;
import com.google.api.client.extensions.jetty.auth.oauth2.LocalServerReceiver;
import com.google.api.client.googleapis.auth.oauth2.GoogleAuthorizationCodeFlow;
import com.google.api.client.googleapis.auth.oauth2.GoogleClientSecrets;
import com.google.api.client.googleapis.javanet.GoogleNetHttpTransport;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.json.JsonFactory;
import com.google.api.client.json.gson.GsonFactory;
import com.google.api.client.util.store.FileDataStoreFactory;
import com.google.api.services.gmail.Gmail;
import com.google.api.services.gmail.GmailScopes;
import com.google.api.services.gmail.model.Label;
import com.google.api.services.gmail.model.ListLabelsResponse;
import com.google.api.services.gmail.model.ListMessagesResponse;
import com.google.api.services.gmail.model.Message;
import com.google.api.services.gmail.model.MessagePart;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/* class to demonstrate use of Gmail list labels API */
public class Main {

    /**
     * Application name.
     */
    private static final String APPLICATION_NAME = "Gmail API Java Quickstart";
    /**
     * Global instance of the JSON factory.
     */
    private static final JsonFactory JSON_FACTORY = GsonFactory.getDefaultInstance();
    /**
     * Directory to store authorization tokens for this application.
     */
    private static final String TOKENS_DIRECTORY_PATH = "tokens";

    /**
     * Global instance of the scopes required by this quickstart.
     * If modifying these scopes, delete your previously saved tokens/ folder.
     */
    private static Set<String> SCOPES = GmailScopes.all();

    private static final String CREDENTIALS_FILE_PATH = "credentials.json";

    /**
     * UserId - Email
     */
    private static final String USERID = "ilyafrolov0711@gmail.com";

    /**
     * Creates an authorized Credential object.
     *
     * @param HTTP_TRANSPORT The network HTTP Transport.
     * @return An authorized Credential object.
     * @throws IOException If the credentials.json file cannot be found.
     */
    private static Credential getCredentials(final NetHttpTransport HTTP_TRANSPORT)
            throws IOException {
        // Load client secrets.
        InputStream in = Main.class.getClassLoader().getResourceAsStream("credentials.json");
        if (in == null) {
            throw new FileNotFoundException("Resource not found: " + CREDENTIALS_FILE_PATH);
        }
        GoogleClientSecrets clientSecrets =
                GoogleClientSecrets.load(JSON_FACTORY, new InputStreamReader(in));

        // Build flow and trigger user authorization request.
        GoogleAuthorizationCodeFlow flow = new GoogleAuthorizationCodeFlow.Builder(
                HTTP_TRANSPORT, JSON_FACTORY, clientSecrets, SCOPES)
                .setDataStoreFactory(new FileDataStoreFactory(new java.io.File(TOKENS_DIRECTORY_PATH)))
                .setAccessType("offline")
                .build();
        LocalServerReceiver receiver = new LocalServerReceiver.Builder().setPort(8888).build();
        Credential credential = new AuthorizationCodeInstalledApp(flow, receiver).authorize(USERID);
        //returns an authorized Credential object.
        return credential;
    }

    private static String extractMessageBody(Message message) {
        String messageBody = "";

        // Check if the message has parts
        if (message.getPayload() != null && message.getPayload().getParts() != null) {
            // Loop through message parts
            for (MessagePart part : message.getPayload().getParts()) {
                if (part.getMimeType().equals("text/plain")) {
                    // Found the plain text part (message body)
                    messageBody = new String(part.getBody().decodeData());
                    break;
                }
            }
        }

        return messageBody;
    }

    public static void main(String[] args) throws IOException, GeneralSecurityException {
        SCOPES = SCOPES.stream()
                .filter(it -> !it.equals(GmailScopes.GMAIL_METADATA)).collect(Collectors.toSet());

        // Build a new authorized API client service.
        final NetHttpTransport HTTP_TRANSPORT = GoogleNetHttpTransport.newTrustedTransport();
        Gmail service = new Gmail.Builder(HTTP_TRANSPORT, JSON_FACTORY, getCredentials(HTTP_TRANSPORT))
                .setApplicationName(APPLICATION_NAME)
                .build();

        ListMessagesResponse msgResponse = service.users().messages().list(USERID).execute();
        List<Message> messages = msgResponse.getMessages().stream()
                .map(Message::getId)
                .map(msgId -> {
                    try {
                        return service.users().messages().get(USERID, msgId).execute();
                    } catch (IOException e) {
                        return null;
                    }
                })
                .filter(Objects::nonNull)
                .toList();

        List<String> links = new ArrayList<>();

        for (int i = 0; i < messages.size(); i++) {
            String regex = "https://ca\\.indeed\\.com/rc/clk/\\S+";
            String msgBody = extractMessageBody(messages.get(i));

            Pattern pattern = Pattern.compile(regex);
            Matcher matcher = pattern.matcher(msgBody);

            while (matcher.find()) {
                String link = matcher.group();
                links.add(link);
            }

        }

        //Writing jobs to files
        String existingFile = "D:/Canada/Jobs/All received jobs.txt";
        String outputFile = "D:/Canada/Jobs/New jobs.txt";

        try {
            FileWriter fileWriter = new FileWriter(existingFile, true);
            BufferedWriter bufferedWriter = new BufferedWriter(fileWriter);
            FileWriter fileWriter2 = new FileWriter(outputFile);
            BufferedWriter bufferedWriter2 = new BufferedWriter(fileWriter2);

            // Check if links exist in the existing file
            String line;
            for (String link : links) {
                // Read existing file
                FileReader fileReader = new FileReader(existingFile);
                BufferedReader bufferedReader = new BufferedReader(fileReader);

                // Read each line in the existing file
                boolean notExist = true;
                while ((line = bufferedReader.readLine()) != null) {
                    // Check if the line contains the target link
                    if (line.contains(link)) {
                        notExist = false;
                        break;
                    }
                }
                bufferedReader.close();

                if (notExist) {
                    bufferedWriter.newLine();
                    bufferedWriter.write(link);

                    bufferedWriter2.newLine();
                    bufferedWriter2.write(link);
                }
            }

            bufferedWriter.close();
            bufferedWriter2.close();

        } catch (IOException e) {
            e.printStackTrace();
            System.err.println("Error writing links to the file.");
        }

    }
}