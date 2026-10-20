/// message error MsalException
class MsalException implements Exception {
  String errorMessage;

  /// MSAL's error code, e.g. `invalid_grant` or `no_tokens_found`; null where the platform reports none.
  final String? errorCode;

  /// The OAuth sub-error, e.g. `basic_action`, `bad_token`.
  final String? subError;

  /// The Microsoft Entra error code, e.g. `AADSTS700082` (refresh token expired from inactivity).
  final String? stsErrorCode;

  MsalException(this.errorMessage,
      {this.errorCode, this.subError, this.stsErrorCode});

  @override
  String toString() => '$runtimeType: $errorMessage'
      '${errorCode == null ? '' : ' (errorCode: $errorCode, subError: $subError, stsErrorCode: $stsErrorCode)'}';
}

/// message error MsalInteractionRequiredException
/// Silent token acquisition needs the user: refresh token expired or revoked,
/// Conditional Access sign-in frequency, password change, …
class MsalInteractionRequiredException extends MsalException {
  MsalInteractionRequiredException(super.errorMessage,
      {super.errorCode, super.subError, super.stsErrorCode});
}

/// message error  MsalChangedClientIdException
class MsalChangedClientIdException extends MsalException {
  MsalChangedClientIdException()
      : super(
            "Cannot create a client with a new client ID. Only 1 client id supported");
}

/// message error MsalUserCancelledException
class MsalUserCancelledException extends MsalException {
  MsalUserCancelledException() : super("User cancelled login request");
}

/// message error MsalNoAccountException
class MsalNoAccountException extends MsalException {
  MsalNoAccountException()
      : super("Cannot login silently. No account available");
}

/// message error MsalInvalidConfigurationException
class MsalInvalidConfigurationException extends MsalException {
  MsalInvalidConfigurationException(errorMessage) : super(errorMessage);
}

/// message error MsalInvalidScopeException
class MsalInvalidScopeException extends MsalException {
  MsalInvalidScopeException() : super("Invalid or no scope");
}

/// message error MsalInitializationException
class MsalInitializationException extends MsalException {
  MsalInitializationException()
      : super(
            "Error initializing client. Please ensure correctly configuration supplied");
}

/// message error MsalUninitializedException
class MsalUninitializedException extends MsalException {
  MsalUninitializedException()
      : super(
            "Client not initialized. Client must be initialized before attempting to use");
}
