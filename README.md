To run properly you need to add the native_app_manifest.json to the registry here:
https://developer.chrome.com/docs/extensions/develop/concepts/native-messaging#native-messaging-host-location

As well as replacing the `"path": "<<FULL_PATH TO BAT FILE>>"` with full path to the `run_native_app.bat` file.

And adding ```"allowed_origins": [
        "chrome-extension://<<EXTENSION_ID>/"
    ]``` id of chrome-extension in here. This can be seen in extensions page when loading the package.


python requires ``cryptography`` and ``pyopenssl` packages
