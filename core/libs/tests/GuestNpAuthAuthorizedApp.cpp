#include "SceTypes.hpp"
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdlib>

struct AuthorizedAppCodeParameter {
    std::size_t size;
    std::int32_t userId;
    std::uint8_t padding[4];
    const void* authorizedAppClientId;
    const char* scope;
    std::int32_t accessType;
    std::uint8_t padding2[4];
};
static_assert(sizeof(AuthorizedAppCodeParameter) == 40);

extern "C" {
int APS5_VABI sceNpAuthCreateAsyncRequest(const void*);
int APS5_VABI sceNpAuthGetAuthorizedAppCode(int, const AuthorizedAppCodeParameter*, void*, int*, bool*);
}

static void Require(bool condition) {
    if (!condition) std::abort();
}

int main() {
    constexpr int invalidArgument = static_cast<int>(0x80550301u);
    constexpr int invalidSize = static_cast<int>(0x80550302u);
    constexpr int signedOut = static_cast<int>(0x80550006u);

    const int request = sceNpAuthCreateAsyncRequest(nullptr);
    Require(request > 0);

    std::uint8_t clientId = 1;
    AuthorizedAppCodeParameter param{};
    param.size = sizeof(param);
    param.authorizedAppClientId = &clientId;
    param.scope = "openid";
    param.accessType = 0;

    std::array<std::uint8_t, 64> code;
    code.fill(0xa5);
    const auto originalCode = code;
    int issuerId = 123;
    bool consentRequired = true;

    Require(sceNpAuthGetAuthorizedAppCode(request, &param, code.data(),
                                         &issuerId, &consentRequired) == signedOut);
    Require(!consentRequired);
    Require(code == originalCode && issuerId == 123);

    Require(sceNpAuthGetAuthorizedAppCode(0, &param, code.data(),
                                         &issuerId, &consentRequired) == invalidArgument);
    Require(sceNpAuthGetAuthorizedAppCode(request, nullptr, code.data(),
                                         &issuerId, &consentRequired) == invalidArgument);
    Require(sceNpAuthGetAuthorizedAppCode(request, &param, nullptr,
                                         &issuerId, &consentRequired) == invalidArgument);
    Require(sceNpAuthGetAuthorizedAppCode(request, &param, code.data(),
                                         &issuerId, nullptr) == invalidArgument);

    param.size -= 8;
    Require(sceNpAuthGetAuthorizedAppCode(request, &param, code.data(),
                                         &issuerId, &consentRequired) == invalidSize);
    param.size = sizeof(param);
    param.scope = nullptr;
    Require(sceNpAuthGetAuthorizedAppCode(request, &param, code.data(),
                                         &issuerId, &consentRequired) == invalidArgument);
    param.scope = "openid";
    param.accessType = 2;
    Require(sceNpAuthGetAuthorizedAppCode(request, &param, code.data(),
                                         &issuerId, &consentRequired) == invalidArgument);
    Require(code == originalCode && issuerId == 123);
}
