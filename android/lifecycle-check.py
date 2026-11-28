"""Run the actual wrapper callbacks on deterministic Android test doubles.

The dispatch model follows Android's documented configChanges contract. This is
not an emulator or proof of real WebView/device behavior. No SDK or dependency
is needed beyond JDK 17 and Python. All input is a disposable public sentinel.
"""
from pathlib import Path
import subprocess
import tempfile
import xml.etree.ElementTree as ET

root = Path(__file__).resolve().parent
manifest = ET.parse(root / 'app/src/main/AndroidManifest.xml')
ns = '{http://schemas.android.com/apk/res/android}'
activity = manifest.find('application/activity')
handled = activity.get(ns + 'configChanges', '').split('|')
declared = ['orientation', 'screenSize', 'screenLayout', 'smallestScreenSize', 'keyboard', 'keyboardHidden']
missing = [name for name in declared if name not in handled]
if missing:
    raise SystemExit(f"MainActivity configChanges is missing {missing}; those changes would recreate the WebView")
rotation_handled = all(name in handled for name in declared)
stubs = {
'android/os/Bundle.java': 'package android.os; public class Bundle extends java.util.HashMap<String,Object> {}',
'android/os/Process.java': 'package android.os; public class Process { public static int kills; public static int myPid(){return 1;} public static void killProcess(int pid){kills++;} }',
'android/content/res/Configuration.java': 'package android.content.res; public class Configuration {}',
'android/content/res/AssetManager.java': 'package android.content.res; public class AssetManager { public java.io.InputStream open(String name)throws Exception{return new java.io.FileInputStream(System.getProperty("asset"));} }',
'android/view/WindowManager.java': 'package android.view; public class WindowManager { public static class LayoutParams { public static final int FLAG_SECURE=8192; } }',
'android/view/Window.java': 'package android.view; public class Window { public int flags; public void setFlags(int value,int mask){flags=value;} }',
'android/view/View.java': '''package android.view; public class View { public static final int GONE=8,VISIBLE=0; public int visibility; public interface OnClickListener {void onClick(View view);} public OnClickListener listener; public void setVisibility(int value){visibility=value;} public void setOnClickListener(OnClickListener value){listener=value;} public Object getParent(){return parent;} public ViewGroup parent; public void invalidate(){invalidations++;} public int invalidations; public int[] padding={0,0,0,0}; public void setPadding(int l,int t,int r,int b){padding=new int[]{l,t,r,b};} public interface OnApplyWindowInsetsListener {WindowInsets onApplyWindowInsets(View view,WindowInsets insets);} public OnApplyWindowInsetsListener insetsListener; public void setOnApplyWindowInsetsListener(OnApplyWindowInsetsListener value){insetsListener=value;} }''',
'android/view/WindowInsets.java': 'package android.view; public class WindowInsets { public static final class Type { public static int systemBars(){return 1;} public static int displayCutout(){return 2;} } final android.graphics.Insets bars,cutout; public WindowInsets(android.graphics.Insets b,android.graphics.Insets c){bars=b;cutout=c;} public android.graphics.Insets getInsets(int mask){android.graphics.Insets n=new android.graphics.Insets(0,0,0,0);return android.graphics.Insets.max((mask&1)!=0?bars:n,(mask&2)!=0?cutout:n);} }',
'android/graphics/Insets.java': 'package android.graphics; public final class Insets { public final int left,top,right,bottom; public Insets(int l,int t,int r,int b){left=l;top=t;right=r;bottom=b;} public static Insets max(Insets a,Insets b){return new Insets(Math.max(a.left,b.left),Math.max(a.top,b.top),Math.max(a.right,b.right),Math.max(a.bottom,b.bottom));} }',
'android/os/Build.java': 'package android.os; public class Build { public static class VERSION_CODES { public static final int R=30; } public static class VERSION { public static final int SDK_INT=35; } }',
'android/view/ViewGroup.java': 'package android.view; public class ViewGroup extends View { public void removeView(View view){view.parent=null;} }',
'android/widget/TextView.java': 'package android.widget; public class TextView extends android.view.View { public String text; public void setText(String value){text=value;} }',
'android/widget/Button.java': 'package android.widget; public class Button extends TextView { public boolean enabled=true; public void setEnabled(boolean value){enabled=value;} public void click(){if(enabled&&listener!=null)listener.onClick(this);} }',
'android/net/Uri.java': 'package android.net; public class Uri { public final String scheme,host,path; public Uri(){this("file",null,"/android_asset/entropylab.html");} public Uri(String s,String h,String p){scheme=s;host=h;path=p;} public String getScheme(){return scheme;} public String getHost(){return host;} public String getPath(){return path;} }',
'android/webkit/WebResourceRequest.java': 'package android.webkit; public interface WebResourceRequest { android.net.Uri getUrl(); }',
'android/webkit/WebViewClient.java': 'package android.webkit; public class WebViewClient { public boolean shouldOverrideUrlLoading(WebView view,WebResourceRequest request){return false;} }',
'android/webkit/WebSettings.java': 'package android.webkit; public class WebSettings { public static final int LOAD_NO_CACHE=2; public void setJavaScriptEnabled(boolean v){} public void setBlockNetworkLoads(boolean v){} public void setAllowFileAccess(boolean v){} public void setAllowContentAccess(boolean v){} public void setDomStorageEnabled(boolean v){} public static Boolean saveFormData; public void setSaveFormData(boolean v){saveFormData=v;} public void setCacheMode(int v){} }',
'android/webkit/WebView.java': '''package android.webkit; public class WebView extends android.view.View { public static Boolean debugging; public static void setWebContentsDebuggingEnabled(boolean value){debugging=value;} public int loads; public boolean destroyed,stopped; public String input=""; public WebSettings getSettings(){return new WebSettings();} public void setWebViewClient(WebViewClient v){} public void loadUrl(String url){loads++;input="";} public void stopLoading(){stopped=true;} public void destroy(){destroyed=true;input="";} }''',
'android/app/Activity.java': '''package android.app; public class Activity { public boolean changing,finished; public int configurations,destroys; public final android.view.Window window=new android.view.Window(); public final java.util.Map<Integer,android.view.View> views=new java.util.HashMap<>(); protected void onCreate(android.os.Bundle b){} protected void onStop(){} protected void onDestroy(){destroys++;} public void onConfigurationChanged(android.content.res.Configuration c){configurations++;} protected void onSaveInstanceState(android.os.Bundle b){b.put("hierarchy",((android.webkit.WebView)views.get(7)).input);} public void performDestroy(){onDestroy();} public void performSave(android.os.Bundle b){onSaveInstanceState(b);} public android.view.Window getWindow(){return window;} public void setContentView(int id){views.put(1,new android.widget.TextView());views.put(2,new android.widget.TextView());views.put(3,new android.widget.TextView());views.put(4,new android.widget.Button());views.put(5,new android.view.View());android.webkit.WebView page=new android.webkit.WebView();page.visibility=android.view.View.GONE;android.view.ViewGroup root=new android.view.ViewGroup();views.put(6,root);page.parent=root;views.put(7,page);} @SuppressWarnings("unchecked") public <T extends android.view.View>T findViewById(int id){return (T)views.get(id);} public android.content.res.AssetManager getAssets(){return new android.content.res.AssetManager();} public boolean isChangingConfigurations(){return changing;} public void finishAndRemoveTask(){finished=true;} }''',
'online/entropylab/android/R.java': 'package online.entropylab.android; public class R { public static class layout {public static final int activity_main=1;} public static class id {public static final int version=1,digest=2,blocked=3,open=4,launch=5,root=6,page=7;} }',
'online/entropylab/android/BuildConfig.java': 'package online.entropylab.android; public class BuildConfig {public static final String HTML_SHA256="'+(root/'ENTROPYLAB_HTML.sha256').read_text().split()[0]+'",ENTROPYLAB_VERSION="test";}',
'online/entropylab/android/LifecycleCheck.java': '''package online.entropylab.android;
import android.os.Bundle; import android.webkit.WebView; import android.widget.Button; import android.widget.TextView; import android.content.res.Configuration;
public class LifecycleCheck {
 static void check(boolean value,String message){if(!value)throw new AssertionError(message);}
 static MainActivity create(Bundle saved){MainActivity a=new MainActivity();a.onCreate(saved);return a;}
 static WebView page(MainActivity a){return a.findViewById(R.id.page);}
 static void open(MainActivity a){((Button)a.findViewById(R.id.open)).click();}
 static MainActivity rotate(MainActivity a,boolean handled){if(handled){a.onConfigurationChanged(new Configuration());return a;} a.changing=true;a.onStop();a.performDestroy();return create(new Bundle());}
 public static void main(String[] args){
 boolean handled=Boolean.parseBoolean(args[0]);
 if(args.length>1&&args[1].equals("refused")){MainActivity t=create(null);Button o=t.findViewById(R.id.open);TextView b=t.findViewById(R.id.blocked);check(!o.enabled&&b.text!=null&&!b.text.isEmpty(),"pin mismatch left Open enabled or showed no refusal");o.enabled=true;o.click();check(page(t).loads==0&&page(t).visibility==android.view.View.GONE&&t.findViewById(R.id.launch).visibility==0,"pin mismatch still loaded the calculator");System.out.println("LifecycleCheck OK: HTML that does not match the pin keeps Open disabled and never loads");return;}
 MainActivity launch=create(null);WebView unopened=page(launch);launch=rotate(launch,handled);check(page(launch)==unopened&&unopened.loads==0&&launch.findViewById(R.id.launch).visibility==0,"launch-screen rotation opened or recreated the calculator");
 MainActivity a=create(null);open(a);WebView original=page(a);original.input="PUBLIC ROTATION TEST ONLY";
 android.view.View root=a.findViewById(R.id.root);check(root.insetsListener!=null,"edge-to-edge (targetSdk 36 on Android 15+): no window-insets listener keeps the page clear of the system bars");
 root.insetsListener.onApplyWindowInsets(root,new android.view.WindowInsets(new android.graphics.Insets(0,63,0,42),new android.graphics.Insets(88,0,0,0)));
 check(java.util.Arrays.equals(root.padding,new int[]{88,63,0,42}),"system-bar and cutout insets were not applied as root padding: "+java.util.Arrays.toString(root.padding));
 check(Boolean.FALSE.equals(WebView.debugging),"WebView debugging was not explicitly disabled");
 check(Boolean.FALSE.equals(android.webkit.WebSettings.saveFormData),"WebView form-data saving was not disabled");
 check(MainActivity.isBundledPage(new android.net.Uri("file",null,"/android_asset/entropylab.html"))&&MainActivity.isBundledPage(new android.net.Uri("file","","/android_asset/entropylab.html")),"bundled page was rejected");
 check(!MainActivity.isBundledPage(new android.net.Uri("file","evil","/android_asset/entropylab.html"))&&!MainActivity.isBundledPage(new android.net.Uri("https",null,"/android_asset/entropylab.html"))&&!MainActivity.isBundledPage(new android.net.Uri("file",null,"/android_asset/other.html"))&&!MainActivity.isBundledPage(null),"navigation check accepted a non-bundled URL");
 for(int i=0;i<8;i++){a=rotate(a,handled);check(page(a)==original,"rotation recreated the WebView and discarded the active calculator session");check(original.loads==1&&original.input.equals("PUBLIC ROTATION TEST ONLY"),"rotation reloaded or lost disposable input");check(!a.finished&&android.os.Process.kills==0,"rotation ended the session");}
 check(original.invalidations==8&&a.configurations==8,"configuration callbacks did not redraw existing WebView");
 Bundle saved=new Bundle();a.performSave(saved);check(saved.isEmpty(),"calculator/view hierarchy was serialized into saved state");
 MainActivity afterDeath=create(saved);check(page(afterDeath).loads==0&&page(afterDeath).input.isEmpty()&&afterDeath.findViewById(R.id.launch).visibility==0,"new process restored calculator state instead of cold launch");
 a.changing=false;a.onStop();a.onStop();check(a.finished&&android.os.Process.kills==1,"real backgrounding must finish task and kill once");
 a.performDestroy();check(original.destroyed&&original.stopped&&original.getParent()==null&&a.destroys==1,"activity cleanup did not detach/destroy the WebView");
 MainActivity recreated=create(null);check(page(recreated).loads==0,"return must require explicit Open");open(recreated);check(page(recreated).loads==1&&page(recreated).input.isEmpty(),"return reused calculator state");
 recreated.changing=true;recreated.onStop();recreated.performDestroy();check(page(recreated).destroyed&&android.os.Process.kills==1,"unhandled recreation must destroy old view without extra process kill");
 System.out.println("LifecycleCheck OK: repeated rotation, no saved state, cold creation/return, background shutdown, destruction (Android test doubles; not device validation)");
 }
}'''
}
with tempfile.TemporaryDirectory(prefix='entropylab-lifecycle-') as tmp:
    tmp = Path(tmp)
    files = []
    for name, text in stubs.items():
        path = tmp / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
        files.append(str(path))
    main = root / 'app/src/main/java/online/entropylab/android'
    files += [str(main/'MainActivity.java'), str(main/'HtmlPin.java')]
    subprocess.run(['javac', '--release', '17', '-d', str(tmp/'classes'), *files], check=True, timeout=180)
    asset = root/'app/src/main/assets/entropylab.html'
    subprocess.run(['java', '-Dasset='+str(asset), '-cp', str(tmp/'classes'), 'online.entropylab.android.LifecycleCheck', str(rotation_handled).lower()], check=True, timeout=30)
    # Fail closed: a packaged page one byte off the pin, or one that cannot be read, never opens.
    tampered = tmp/'tampered.html'
    tampered.write_bytes(asset.read_bytes() + b'\n')
    for bad in (tampered, tmp/'missing.html'):
        subprocess.run(['java', '-Dasset='+str(bad), '-cp', str(tmp/'classes'), 'online.entropylab.android.LifecycleCheck', str(rotation_handled).lower(), 'refused'], check=True, timeout=30)
