package online.entropylab.android;

import android.app.Activity;
import android.net.Uri;
import android.os.Bundle;
import android.view.WindowManager;
import android.webkit.WebResourceRequest;
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import android.widget.Button;
import android.widget.TextView;
import java.io.InputStream;

/**
 * Launch screen, then the bundled release HTML. No URL bar, no network
 * permission, no keystore. Leaving the activity kills the process.
 */
public final class MainActivity extends Activity {
    private boolean shuttingDown;
    private boolean hashMatches;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        getWindow().setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE);
        setContentView(R.layout.activity_main);
        String digest = hashAsset();
        hashMatches = digest.equals(BuildConfig.HTML_SHA256);
        TextView version = findViewById(R.id.version);
        version.setText("EntropyLab " + BuildConfig.ENTROPYLAB_VERSION);
        TextView digestView = findViewById(R.id.digest);
        digestView.setText(digest);
        TextView blocked = findViewById(R.id.blocked);
        Button open = findViewById(R.id.open);
        if (!hashMatches) {
            blocked.setText("Embedded HTML does not match the pinned SHA-256. The calculator will not open.");
            open.setEnabled(false);
            return;
        }
        open.setOnClickListener(view -> showPage());
    }

    private String hashAsset() {
        try (InputStream input = getAssets().open("entropylab.html")) {
            return HtmlPin.sha256(input);
        } catch (Exception exception) {
            return "unreadable";
        }
    }

    private void showPage() {
        if (!hashMatches || shuttingDown) return;
        WebView page = findViewById(R.id.page);
        WebSettings settings = page.getSettings();
        settings.setJavaScriptEnabled(true);
        settings.setBlockNetworkLoads(true);
        // file:///android_asset/ URLs stay reachable even with file access off.
        settings.setAllowFileAccess(false);
        settings.setAllowContentAccess(false);
        settings.setDomStorageEnabled(false);
        settings.setCacheMode(WebSettings.LOAD_NO_CACHE);
        page.setWebViewClient(new WebViewClient() {
            @Override
            public boolean shouldOverrideUrlLoading(WebView view, WebResourceRequest request) {
                Uri uri = request.getUrl();
                return uri == null || !"file".equals(uri.getScheme()) || !"/android_asset/entropylab.html".equals(uri.getPath());
            }
        });
        findViewById(R.id.launch).setVisibility(android.view.View.GONE);
        page.setVisibility(android.view.View.VISIBLE);
        page.loadUrl("file:///android_asset/entropylab.html");
    }

    @Override
    protected void onStop() {
        super.onStop();
        if (!isChangingConfigurations()) shutDown();
    }

    private void shutDown() {
        if (shuttingDown) return;
        shuttingDown = true;
        finishAndRemoveTask();
        android.os.Process.killProcess(android.os.Process.myPid());
    }
}
