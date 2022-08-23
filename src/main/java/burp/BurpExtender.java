package burp;

import com.github.trganda.ImportContextMenuFactory;

import java.io.PrintWriter;

public class BurpExtender implements IBurpExtender
{
    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks)
    {
        // set our extension name
        callbacks.setExtensionName("Yaml Poc Loader");

        ImportContextMenuFactory menuFactory = new ImportContextMenuFactory(callbacks);
        callbacks.registerContextMenuFactory(menuFactory);
        
        // obtain our output and error streams
        PrintWriter stdout = new PrintWriter(callbacks.getStdout(), true);
        PrintWriter stderr = new PrintWriter(callbacks.getStderr(), true);

        // write a message to our output stream
        stdout.println("Loaded Yaml Poc Loader");

        // write a message to the Burp alerts tab
        callbacks.issueAlert("Hello alerts");
    }
}