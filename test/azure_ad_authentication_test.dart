import 'package:azure_ad_authentication/azure_ad_authentication.dart';
import 'package:azure_ad_authentication/exeption.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  const channel = MethodChannel('azure_ad_authentication');
  TestWidgetsFlutterBinding.ensureInitialized();

  late PlatformException silentError;

  setUp(() {
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(channel, (call) async {
      if (call.method == 'acquireTokenSilent') throw silentError;
      return true;
    });
  });

  tearDown(() {
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(channel, null);
  });

  Future<Object> silentFailure() async {
    final pca = await AzureAdAuthentication.createPublicClientApplication(
        clientId: 'client', authority: 'https://login.microsoftonline.com/x');
    try {
      await pca.acquireTokenSilent(scopes: ['scope']);
    } catch (e) {
      return e;
    }
    fail('acquireTokenSilent did not throw');
  }

  test('INTERACTION_REQUIRED carries the structured error details', () async {
    silentError = PlatformException(
      code: 'INTERACTION_REQUIRED',
      message: 'AADSTS700082: The refresh token has expired due to inactivity.',
      details: {
        'errorCode': 'invalid_grant',
        'subError': 'bad_token',
        'stsErrorCode': 'AADSTS700082',
      },
    );

    expect(
      await silentFailure(),
      isA<MsalInteractionRequiredException>()
          .having((e) => e.errorCode, 'errorCode', 'invalid_grant')
          .having((e) => e.subError, 'subError', 'bad_token')
          .having((e) => e.stsErrorCode, 'stsErrorCode', 'AADSTS700082'),
    );
  });

  test('a non-map details value leaves the structured fields empty', () async {
    silentError = PlatformException(
        code: 'AUTH_ERROR', message: 'boom', details: 'legacy string');

    expect(
      await silentFailure(),
      isA<MsalException>()
          .having((e) => e.errorMessage, 'errorMessage', 'boom')
          .having((e) => e.errorCode, 'errorCode', isNull),
    );
  });

  test('CANCELLED becomes MsalUserCancelledException', () async {
    silentError = PlatformException(code: 'CANCELLED');

    expect(await silentFailure(), isA<MsalUserCancelledException>());
  });
}
