package com.fsconceicao.azure_ad_authentication

import android.app.Activity
import android.content.Context
import android.os.Handler
import android.os.Looper
import android.util.Log
import com.microsoft.identity.client.*
import com.microsoft.identity.client.IPublicClientApplication.IMultipleAccountApplicationCreatedListener
import com.microsoft.identity.client.exception.MsalClientException
import com.microsoft.identity.client.exception.MsalException
import com.microsoft.identity.client.exception.MsalServiceException
import com.microsoft.identity.client.exception.MsalUiRequiredException
import io.flutter.embedding.android.FlutterActivity
import io.flutter.plugin.common.MethodChannel

class Msal(context: Context, activity: FlutterActivity?) {
    internal val applicationContext = context
    internal var activity: FlutterActivity? = activity

    lateinit var adAuthentication: IMultipleAccountPublicClientApplication
    lateinit var accountList: List<IAccount>

    fun setActivity(activity: FlutterActivity) {
        this.activity = activity;
    }

    internal fun isClientInitialized(): Boolean = ::adAuthentication.isInitialized

    internal fun getApplicationCreatedListener(result: MethodChannel.Result): IMultipleAccountApplicationCreatedListener {

        return object : IMultipleAccountApplicationCreatedListener {
            override fun onCreated(application: IMultipleAccountPublicClientApplication) {
                adAuthentication = application
                result.success(true)
            }

            override fun onError(exception: MsalException?) {
                result.error(
                    "INIT_ERROR",
                    "Error initializting client = ${exception.toString()}",
                    exception?.localizedMessage
                )
            }
        }
    }

    internal fun getAuthCallback(result: MethodChannel.Result): AuthenticationCallback {
        return object : AuthenticationCallback {
            override fun onSuccess(authenticationResult: IAuthenticationResult) {
                Handler(Looper.getMainLooper()).post {
                    result.success("{\"accessToken\":\"${authenticationResult.accessToken}\",\"expiresOn\":\"${authenticationResult.expiresOn}\"}")
                }
            }

            override fun onError(exception: MsalException) {
                Handler(Looper.getMainLooper()).post {
                    result.error(
                        "AUTH_ERROR",
                        "Authentication failed ${exception.localizedMessage}",
                        errorDetails(exception)
                    )
                }
            }

            override fun onCancel() {
                Handler(Looper.getMainLooper()).post {
                    result.error("CANCELLED", "User cancelled", null)
                }
            }
        }
    }

    /**
     * Callback used in for silent acquireToken calls.
     */
    internal fun getAuthSilentCallback(result: MethodChannel.Result): SilentAuthenticationCallback {
        return object : SilentAuthenticationCallback {
            override fun onSuccess(authenticationResult: IAuthenticationResult) {
                Handler(Looper.getMainLooper()).post {
                    result.success("{\"accessToken\":\"${authenticationResult.accessToken}\",\"expiresOn\":\"${authenticationResult.expiresOn}\"}")
                }
            }

            override fun onError(exception: MsalException) {
                Handler(Looper.getMainLooper()).post {
                    when (exception) {
                        // First: the most specific type must win over the generic client/service branches.
                        // Refresh token expired or revoked, Conditional Access sign-in frequency, password change, …
                        is MsalUiRequiredException -> {
                            result.error(
                                "INTERACTION_REQUIRED",
                                exception.localizedMessage,
                                errorDetails(exception)
                            )
                        }
                        is MsalClientException -> {
                            result.error(
                                "NO_SCOPE",
                                "Call must include a scope",
                                errorDetails(exception)
                            )
                        }
                        is MsalServiceException -> {
                            result.error(
                                "NO_SCOPE",
                                exception.localizedMessage,
                                errorDetails(exception)
                            )
                        }
                        // Every branch must complete the result, otherwise the Dart future never returns.
                        else -> {
                            Log.d("MSAL_FLUTTER", "Authentication failed: $exception")
                            result.error(
                                "AUTH_ERROR",
                                exception.localizedMessage,
                                errorDetails(exception)
                            )
                        }
                    }
                }
            }
        }
    }

    /**
     * Load currently signed-in accounts, if there's any.
     */
    internal fun loadAccounts(result: MethodChannel.Result) {

        adAuthentication.getAccounts(object : IPublicClientApplication.LoadAccountsCallback {

            override fun onTaskCompleted(resultList: List<IAccount>) {
                accountList = resultList
                result.success(true)
            }

            override fun onError(exception: MsalException) {
                result.error(
                    "NO_ACCOUNT",
                    "No account is available to acquire token silently for",
                    exception.localizedMessage
                )
            }
        })
    }


    /**
     * The structured parts of an MSAL error, same keys as on iOS: `errorCode` (e.g. invalid_grant, no_tokens_found),
     * `subError` (e.g. basic_action) and `stsErrorCode` (e.g. AADSTS700082). MSAL Android has no accessor for the STS
     * code, but puts the server's description, which starts with it, into the message.
     */
    private fun errorDetails(exception: MsalException): Map<String, String> {
        val details = mutableMapOf("errorCode" to exception.errorCode)
        if (exception is MsalUiRequiredException) {
            exception.oauthSubErrorCode?.let { details["subError"] = it }
        }
        Regex("AADSTS\\d+").find(exception.message.orEmpty())?.let { details["stsErrorCode"] = it.value }
        return details
    }

}

