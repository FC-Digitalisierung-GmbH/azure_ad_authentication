import Flutter
import UIKit
import MSAL

public class SwiftAzureAdAuthenticationPlugin: NSObject, FlutterPlugin {
    
    //static fields as initialization isn't really required
    static var clientId : String = ""
    static var authority : String = ""
    static var redirectUri: String?;
    
    static let kCurrentAccountIdentifier = "MSALCurrentAccountIdentifier"
    
    public static func register(with registrar: FlutterPluginRegistrar) {
        let channel = FlutterMethodChannel(name: "azure_ad_authentication", binaryMessenger: registrar.messenger())
        let instance = SwiftAzureAdAuthenticationPlugin()
        registrar.addMethodCallDelegate(instance, channel: channel)
    }
    
    
    
    public func handle(_ call: FlutterMethodCall, result: @escaping FlutterResult)
    {
        //get the arguments as a dictionary
        let dict = call.arguments! as! NSDictionary
        let scopes = dict["scopes"] as? [String] ?? [String]()
        let clientId = dict["clientId"] as? String ?? ""
        let authority = dict["authority"] as? String ?? ""
        let redirectUri = dict["redirectUri"] as? String ?? nil
        
        switch( call.method ){
        case "initialize": initialize(clientId: clientId, authority: authority, redirectUri: redirectUri, result: result)
        case "acquireToken": acquireToken(scopes: scopes, result: result)
        case "acquireTokenSilent": acquireTokenSilent(scopes: scopes, result: result)
        case "logout": logout(result: result)
        default: result(FlutterError(code:"INVALID_METHOD", message: "The method called is invalid", details: nil))
        }
    }
    
    
    fileprivate func getResultLogin(_ authResult: MSALResult) -> String?{
        // Get access token from result
        let jsonObject:[String : Any] = ["accessToken":authResult.accessToken, "expiresOn": "\(String(describing: authResult.expiresOn))"];
        let signedInAccount = authResult.account
        self.currentAccountIdentifier = signedInAccount.homeAccountId?.identifier
        
        do{
            
            let jsonData = try JSONSerialization.data(withJSONObject: jsonObject, options: .prettyPrinted)
            if let jsonString:String = String(data: jsonData, encoding: .utf8){
                return jsonString
            }
            
        }catch {
            print(error.localizedDescription)
        }
        return nil
    }
    
    private func initialize(clientId: String, authority: String,redirectUri: String?, result: @escaping FlutterResult)
    {
        //validate clientid exists
        if(clientId.isEmpty){
            result(FlutterError(code:"NO_CLIENTID", message: "Call must include a clientId", details: nil))
            return
        }
        
        SwiftAzureAdAuthenticationPlugin.clientId = clientId;
        SwiftAzureAdAuthenticationPlugin.authority = authority;
        SwiftAzureAdAuthenticationPlugin.redirectUri = redirectUri;
        result(true)
    }
    
    
}
//MARK: - Get token
extension SwiftAzureAdAuthenticationPlugin {
    
    private func acquireToken(scopes: [String], result: @escaping FlutterResult)
    {
        if let application = getApplication(result: result){
            
            
            // No foreground window (e.g. the app went to the background): report it instead of crashing on a nil
            // presenter.
            guard let viewController = UIViewController.keyViewController else {
                result(FlutterError(code: "AUTH_ERROR", message: "No foreground window to present the sign-in on", details: nil))
                return
            }
            let webviewParameters = MSALWebviewParameters(authPresentationViewController: viewController)
            if #available(iOS 13.0, *) {
                webviewParameters.prefersEphemeralWebBrowserSession = true
                #if targetEnvironment(simulator)
                webviewParameters.webviewType = MSALWebviewType.wkWebView
                #endif
            }
            
            removeAccount(application)
            
            let interactiveParameters = MSALInteractiveTokenParameters(scopes: scopes, webviewParameters: webviewParameters)
            
            application.acquireToken(with: interactiveParameters, completionBlock: { (msalresult, error) in
                guard let authResult = msalresult, error == nil else {
                    let nsError = error as NSError?
                    let cancelled = nsError?.domain == MSALErrorDomain
                        && nsError?.code == MSALError.userCanceled.rawValue
                    if cancelled {
                        result(FlutterError(code: "CANCELLED", message: "User cancelled", details: nil))
                    } else {
                        result(FlutterError(code: "AUTH_ERROR", message: self.errorMessage(nsError), details: self.errorDetails(nsError)))
                    }
                    return
                }

                result(self.getResultLogin(authResult))
            })
        }
        else {
            return
        }
        
    }
}
//MARK: - Get token silent
extension SwiftAzureAdAuthenticationPlugin {
    
    private func acquireTokenSilent(scopes: [String], result: @escaping FlutterResult)
    {
        if let application = getApplication(result: result){
            guard let account = currentAccount(application) else{
                result(FlutterError(code: "NO_ACCOUNT",  message: "No account is available to acquire token silently for", details: nil))
                return
            }
            
            let silentParameters = MSALSilentTokenParameters(scopes: scopes, account: account)
            
            application.acquireTokenSilent(with: silentParameters, completionBlock: { (msalresult, error) in
                
                guard let authResult = msalresult, error == nil else {
                    let nsError = error as NSError?
                    // Refresh token expired or revoked, Conditional Access sign-in frequency, password change, …
                    let interactionRequired = nsError?.domain == MSALErrorDomain
                        && nsError?.code == MSALError.interactionRequired.rawValue
                    result(FlutterError(
                        code: interactionRequired ? "INTERACTION_REQUIRED" : "AUTH_ERROR",
                        message: self.errorMessage(nsError),
                        details: self.errorDetails(nsError)))
                    return
                }

                result(self.getResultLogin(authResult))

            })
        }
        else {
            return
        }
    }
}
//MARK: - Error details
extension SwiftAzureAdAuthenticationPlugin {

    /// MSAL puts the server's description (with the AADSTS code) under its own key, not NSLocalizedDescriptionKey, so
    /// localizedDescription alone is the generic Cocoa text.
    fileprivate func errorMessage(_ nsError: NSError?) -> String {
        return nsError?.userInfo[MSALErrorDescriptionKey] as? String
            ?? nsError?.localizedDescription
            ?? "Authentication error"
    }

    /// The structured parts of an MSAL error, same keys as on Android: `errorCode` (OAuth error, e.g. invalid_grant,
    /// or the MSAL error code), `subError` (e.g. basic_action) and `stsErrorCode` (e.g. AADSTS700082, from the description).
    fileprivate func errorDetails(_ nsError: NSError?) -> [String: String]? {
        guard let nsError = nsError else { return nil }
        var details = [String: String]()
        details["errorCode"] = nsError.userInfo[MSALOAuthErrorKey] as? String ?? "msal_\(nsError.code)"
        if let subError = nsError.userInfo[MSALOAuthSubErrorKey] as? String {
            details["subError"] = subError
        }
        // MSAL has no public key for the STS code, but the server's description starts with it.
        let description = errorMessage(nsError)
        if let range = description.range(of: "AADSTS\\d+", options: .regularExpression) {
            details["stsErrorCode"] = String(description[range])
        }
        return details
    }
}
//MARK: - Get logout remove or count cachedAccounts
extension SwiftAzureAdAuthenticationPlugin {
    
    fileprivate func removeAccount(_ application: MSALPublicClientApplication) {
        do{
            var msalAcount:MSALAccount?
            if let accountIndetifier = currentAccountIdentifier {
                let parameters = MSALAccountEnumerationParameters(identifier: accountIndetifier)
                application.accountsFromDevice(for: parameters, completionBlock:{(accounts, error) in
                    if(accounts != nil && !accounts!.isEmpty){
                        msalAcount = accounts?.first;
                    }
                    if error != nil
                    {
                        print(error?.localizedDescription ?? "N/A")
                    }
                })
            }
            
            if let account = msalAcount {
                try application.remove(account)
                
            }
        }catch{
            return
        }
    }
    
    fileprivate func signOut(_ application: MSALPublicClientApplication, _ account: MSALAccount, result: @escaping FlutterResult) {
        let viewController: UIViewController = UIViewController.keyViewController!
        let webviewParameters = MSALWebviewParameters(authPresentationViewController: viewController)
        webviewParameters.webviewType = .default
        
        let signoutParameters = MSALSignoutParameters(webviewParameters: webviewParameters)
        signoutParameters.signoutFromBrowser = false
        
        application.signout(with: account, signoutParameters: signoutParameters, completionBlock: {(success, error) in
            
            if error != nil {
                result(FlutterError(code: "Signout failed", message: "Signout failed", details: nil))
                return
            }
            // Sign out completed successfully
            result(true)
        })
    }
    
    private func logout(result: @escaping FlutterResult)
    {
        
        if let application = getApplication(result: result){
            do{
                
                guard let accountToDelete = currentAccount(application) else{
                    result(FlutterError(code: "CONFIG_ERROR", message: "Unable get remove accounts Null", details: nil))
                    return
                }
                
                clearCurrentAccount()
                try application.remove(accountToDelete)
                removeAccount(application)
            } catch {
                result(FlutterError(code: "CONFIG_ERROR", message: "Unable get remove accounts", details: nil))
                return
            }
            
            result(true)
            return
        }
        else {
            // getApplication(result:) has already replied.
            return
        }
    }
    
    
    
    
    var currentAccountIdentifier: String? {
        get {
            return UserDefaults.standard.string(forKey: SwiftAzureAdAuthenticationPlugin.kCurrentAccountIdentifier)
        }
        set (accountIdentifier) {
            // The identifier in the MSALAccount is the key to retrieve this user from
            // the cache in the future. Save this piece of information in a place you can
            // easily retrieve in your app. In this case we're going to store it in
            // NSUserDefaults.
            UserDefaults.standard.set(accountIdentifier, forKey: SwiftAzureAdAuthenticationPlugin.kCurrentAccountIdentifier)
        }
    }
    
    // We retrieve our current account by checking for the accountIdentifier that we stored in NSUserDefaults when
    // we first signed in the account. Answers nothing on the channel: the caller sends the one reply.
    fileprivate func currentAccount(_ application: MSALPublicClientApplication) -> MSALAccount? {
        guard let accountIdentifier = currentAccountIdentifier,
              let account = try? application.account(forIdentifier: accountIdentifier) else {
            clearCurrentAccount()
            return nil
        }
        return account
    }
    
    
    func clearCurrentAccount() {
        // Leave around the account identifier as the last piece of state to clean up as you will probably need
        // it to clean up user-specific state
        UserDefaults.standard.removeObject(forKey: SwiftAzureAdAuthenticationPlugin.kCurrentAccountIdentifier)
    }
    
}
//MARK: - get Application config
extension SwiftAzureAdAuthenticationPlugin {
    private func getApplication(result: @escaping FlutterResult) -> MSALPublicClientApplication?
    {
        if(SwiftAzureAdAuthenticationPlugin.clientId.isEmpty){
            result(FlutterError(code: "NO_CLIENT", message: "Client must be initialized before attempting to acquire a token.", details: nil))
            return nil
        }
        
        var config: MSALPublicClientApplicationConfig
        
        //setup the config, using authority if it is set, or defaulting to msal's own implementation if it's not
        if !SwiftAzureAdAuthenticationPlugin.authority.isEmpty
        {
            //try creating the msal aad authority object
            do{
                //create authority url
                guard let authorityUrl = URL(string: SwiftAzureAdAuthenticationPlugin.authority) else{
                    result(FlutterError(code: "INVALID_AUTHORITY", message: "invalid authority", details: nil))
                    return nil
                }
                
                //create the msal authority and configuration
                let msalAuthority = try MSALAuthority(url: authorityUrl)
                config = MSALPublicClientApplicationConfig(clientId: SwiftAzureAdAuthenticationPlugin.clientId, redirectUri: SwiftAzureAdAuthenticationPlugin.redirectUri, authority: msalAuthority)
            } catch {
                //return error if exception occurs
                result(FlutterError(code: "INVALID_AUTHORITY", message: "invalid authority", details: nil))
                return nil
            }
        }
        else
        {
            config = MSALPublicClientApplicationConfig(clientId: SwiftAzureAdAuthenticationPlugin.clientId)
        }
        
        //create the application and return it
        if let application = try? MSALPublicClientApplication(configuration: config)
        {
            // application.validateAuthority = false
            return application
        }else{
            result(FlutterError(code: "CONFIG_ERROR", message: "Unable to create MSALPublicClientApplication", details: nil))
            return nil
        }
    }
}

//MARK: - UIViewController
extension UIViewController {
    
    
    static var keyViewController: UIViewController?{
        if #available(iOS 15, *){
            return UIApplication.shared.connectedScenes.filter({$0.activationState == .foregroundActive}).compactMap({$0 as? UIWindowScene}).first?.windows.filter({$0.isKeyWindow}).first?.rootViewController
        }else{
            return UIApplication.shared.windows.first(where: {$0.isKeyWindow})?.rootViewController
        }
    }
    
}
