package com.fsconceicao.azure_ad_authentication

import android.os.Handler
import android.os.Looper
import android.util.Log
import com.microsoft.identity.client.*
import com.microsoft.identity.client.exception.MsalException
import io.flutter.plugin.common.BinaryMessenger
import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel
import org.jetbrains.annotations.Nullable
import org.json.JSONObject
import java.util.*


class MsalHandlerImpl(private val msal: Msal) : MethodChannel.MethodCallHandler {
    private val TAG = "MsalHandlerImpl"

    @Nullable
    private var channel: MethodChannel? = null

    fun startListening(messenger: BinaryMessenger) {
        if (channel != null) {
            Log.wtf(TAG, "Setting a method call handler before the last was disposed.")
            stopListening()
        }

        channel = MethodChannel(messenger, "azure_ad_authentication")
        channel!!.setMethodCallHandler(this)
    }

    fun stopListening() {
        if (channel == null) {
            Log.d(TAG, "Tried to stop listening when no MethodChannel had been initialized.")
            return
        }

        channel!!.setMethodCallHandler(null)
        channel = null
    }

    override fun onMethodCall(call: MethodCall, result: MethodChannel.Result) {
        Log.d("DART/NATIVE", "onMethodCall ${call.method}")
        val scopesArg: ArrayList<String>? = call.argument("scopes")
        val scopes: Array<String>? = scopesArg?.toTypedArray()
        val clientId: String? = call.argument("clientId")
        val authority: String? = call.argument("authority")
        val redirectUri: String? = call.argument("redirectUri")
        //our code
        when (call.method) {
            "initialize" -> {
                initialize(clientId, authority, redirectUri, result)
            }
            "loadAccounts" -> Thread(Runnable { msal.loadAccounts(result) }).start()
            "acquireToken" -> Thread(Runnable { acquireToken(scopes, result) }).start()
            "acquireTokenSilent" -> Thread(Runnable { acquireTokenSilent(scopes, result) }).start()
            "logout" -> Thread(Runnable { logout(result) }).start()
            else -> result.notImplemented()
        }

    }

    private fun logout(result: MethodChannel.Result) {
        if (!msal.isClientInitialized()) {
            Handler(Looper.getMainLooper()).post {
                result.error(
                    "NO_ACCOUNT",
                    "No account is available to acquire token silently for",
                    null
                )
            }
            return
        }

        if (msal.accountList.isEmpty()) {
            Handler(Looper.getMainLooper()).post {
                result.error(
                    "NO_ACCOUNT",
                    "No account is available to acquire token silently for",
                    null
                )
            }
            return
        }

        msal.adAuthentication.removeAccount(
            msal.accountList.first(),
            object : IMultipleAccountPublicClientApplication.RemoveAccountCallback {
                override fun onRemoved() {
                    Thread(Runnable { msal.loadAccounts(result) }).start()
                }

                override fun onError(exception: MsalException) {
                    result.error(
                        "NO_ACCOUNT",
                        "No account is available to acquire token silently for",
                        exception
                    )
                }
            })


    }

    private fun acquireTokenSilent(scopes: Array<String>?, result: MethodChannel.Result) {
        //  check if client has been initialized

        if (!msal.isClientInitialized()) {
            Handler(Looper.getMainLooper()).post {
                result.error(
                    "NO_CLIENT",
                    "Client must be initialized before attempting to acquire a token.",
                    ""
                )
            }
        }

        //check the scopes
        if (scopes == null) {
            Handler(Looper.getMainLooper()).post {
                result.error("NO_SCOPE", "Call must include a scope", null)
            }
            return
        }

        //ensure accounts exist
        if (msal.accountList.isEmpty()) {
            Handler(Looper.getMainLooper()).post {
                result.error(
                    "NO_ACCOUNT",
                    "No account is available to acquire token silently for",
                    null
                )
            }
            return
        }
        val selectedAccount: IAccount = msal.accountList.first()
        //acquire the token and return the result
        val sc = scopes.map { s -> s.lowercase(Locale.ROOT) }.toTypedArray()

        val builder = AcquireTokenSilentParameters.Builder()
        builder.withScopes(scopes.toList())
            .forAccount(selectedAccount)
            .fromAuthority(selectedAccount.authority)
            .withCallback(msal.getAuthCallback(result))
        val acquireTokenParameters = builder.build()
        msal.adAuthentication.acquireTokenSilentAsync(acquireTokenParameters)
    }

    private fun acquireToken(scopes: Array<String>?, result: MethodChannel.Result) {
        if (!msal.isClientInitialized()) {
            Handler(Looper.getMainLooper()).post {
                result.error(
                    "NO_CLIENT",
                    "Client must be initialized before attempting to acquire a token.",
                    null
                )
            }
        }

        if (scopes == null) {
            result.error("NO_SCOPE", "Call must include a scope", null)
            return
        }

        //remove old accounts
        while (msal.adAuthentication.accounts.any())
            msal.adAuthentication.removeAccount(msal.adAuthentication.accounts.first())


        //acquire the token

        msal.activity.let {
            val builder = AcquireTokenParameters.Builder()
            builder.startAuthorizationFromActivity(it?.activity)
                .withScopes(scopes.toList())
                .withPrompt(Prompt.LOGIN)
                .withCallback(msal.getAuthCallback(result))
            val acquireTokenParameters = builder.build()
            msal.adAuthentication.acquireToken(acquireTokenParameters)
        }
    }

    private fun initialize(clientId: String?, authority: String?, redirectUri: String?, result: MethodChannel.Result) {
        //ensure clientid provided
        if (clientId == null) {
            result.error("NO_CLIENTID", "Call must include a clientId", null)
            return
        }

        //if already initialized, ensure clientid hasn't changed

        if (msal.isClientInitialized()) {
            Log.d("initialize = TRUE", "${msal.isClientInitialized()}")
            if (msal.adAuthentication.configuration.clientId == clientId) {
                result.success(true)
            } else {
                result.error(
                    "CHANGED_CLIENTID",
                    "Attempting to initialize with multiple clientIds.",
                    null
                )
            }
        }
        if (!msal.isClientInitialized()) {
            // if authority is set, create client using it, otherwise use default
            if (authority != null || redirectUri != null) {
                // get json config from raw resource
                val config = msal.applicationContext.resources.openRawResource(R.raw.msal_default_config)
                    .bufferedReader().use { it.readText() }
                // parse json config
                val configJson = JSONObject(config)
                if (authority != null) {
                    // get tenant_id from authority string (https://login.microsoftonline.com/3f9f5fd2-5517-43f7-baa3-63ee31f79721)
                    val tenantId = authority.split("/").last()
                    // "authorities":[
                    //    {
                    //      "type":"AAD",
                    //      "audience":{
                    //        "type":"AzureADMyOrg",
                    //        "tenant_id":"xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
                    //      }
                    //    }
                    //  ]
                    // Replace the default tenant_id in with the one provided by the user
                    Log.d("msal", "Replacing tenant_id with $tenantId")
                    configJson.getJSONArray("authorities").getJSONObject(0).getJSONObject("audience")
                        .put("tenant_id", tenantId)
                }
                if (redirectUri != null) {
                    // "redirect_uri": "msauth://app.prio365.prod/2ZlH1zdUYG9x%2FNshnrFk%2Bb9fhds%3D",
                    // Replace the default redirect_uri in with the one provided by the user
                    Log.d("msal", "Replacing redirect_uri with $redirectUri")
                    configJson.put("redirect_uri", redirectUri)
                }
                // set the client_id
                configJson.put("client_id", clientId)

                // save the updated config into the application support directory
                msal.applicationContext.openFileOutput("msal_custom_config.json", 0).use {
                    it.write(configJson.toString().toByteArray())
                }
                // get the updated config file from the application support directory as File object
                val configFile =
                    msal.applicationContext.getFileStreamPath("msal_custom_config.json")
                PublicClientApplication.createMultipleAccountPublicClientApplication(
                    msal.applicationContext,
                    configFile, msal.getApplicationCreatedListener(result)
                )
            } else {
                PublicClientApplication.createMultipleAccountPublicClientApplication(
                    msal.applicationContext,
                    R.raw.msal_default_config, msal.getApplicationCreatedListener(result)
                )

            }
        }
    }

}