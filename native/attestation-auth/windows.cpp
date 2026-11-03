#include <windows.h>
#include <UserConsentVerifierInterop.h>
#include <winrt/Windows.Foundation.h>
#include <winrt/Windows.Security.Credentials.UI.h>
#include <cstdlib>
#include <string>

int wmain(int argc, wchar_t** argv) {
  if (argc != 3) return 3;
  wchar_t* end = nullptr;
  const auto handle = std::wcstoull(argv[1], &end, 16);
  const auto owner = reinterpret_cast<HWND>(handle);
  const std::wstring reason(argv[2]);
  if (!end || *end || !IsWindow(owner) || reason.empty() || reason.size() > 512) return 3;
  try {
    winrt::init_apartment(winrt::apartment_type::multi_threaded);
    using namespace winrt::Windows::Security::Credentials::UI;
    using Operation = winrt::Windows::Foundation::IAsyncOperation<UserConsentVerificationResult>;
    const auto factory = winrt::get_activation_factory<UserConsentVerifier, IUserConsentVerifierInterop>();
    Operation operation{nullptr};
    winrt::check_hresult(factory->RequestVerificationForWindowAsync(
      owner, winrt::get_abi(winrt::hstring(reason)), winrt::guid_of<Operation>(), winrt::put_abi(operation)));
    const auto result = operation.get();
    if (result == UserConsentVerificationResult::Verified) return 0;
    return result == UserConsentVerificationResult::Canceled ? 2 : 3;
  } catch (...) {
    return 3;
  }
}
