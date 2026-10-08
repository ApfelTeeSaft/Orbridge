#include <cstdint>
#include <cstddef>
#include <atomic>
#include "SceTypes.hpp"
#include "prx/libc/include/General.hpp"

static constexpr int SCE_NP_ERROR_INVALID_ARGUMENT = static_cast<int>(0x80550003);
static constexpr int SCE_NP_ERROR_SIGNED_OUT = static_cast<int>(0x80550006);
static constexpr int NP_POLL_ASYNC_FINISHED = 0;
static constexpr int SCE_NP_AUTH_ERROR_INVALID_ARGUMENT = static_cast<int>(0x80550301u);
static constexpr int SCE_NP_AUTH_ERROR_INVALID_SIZE = static_cast<int>(0x80550302u);

// PS5 SceNpAuthGetAuthorizedAppCodeParameter on x86-64.
// The client ID and scope are borrowed pointers; no token is fabricated.
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


static std::atomic<int> g_nextRequest{1};

extern "C" {

int APS5_VABI sceNpAuthAbortRequest(int req_id) {
 (void)req_id;
 return 0;
}

int APS5_VABI sceNpAuthCreateAsyncRequest(const void* param) {
 (void)param;
 return g_nextRequest.fetch_add(1, std::memory_order_relaxed);
}

int APS5_VABI sceNpAuthCreateRequest(void) {
 NotImplemented_nid_no_patch(__func__);
 return 0;
}

int APS5_VABI sceNpAuthDeleteRequest(int req_id) {
 (void)req_id;
 return 0;
}

int APS5_VABI sceNpAuthGetAuthorizationCodeV3(int req_id, const void* param, void* auth_code, int* issuer_id) {
 (void)req_id;
 (void)issuer_id;
 if (!param || !auth_code) return SCE_NP_ERROR_INVALID_ARGUMENT;
 return SCE_NP_ERROR_SIGNED_OUT;
}

// Offline compatibility: the host has no authenticated PSN session and
// cannot issue Sony authorization codes. Report signed-out, not success.
int APS5_VABI sceNpAuthGetAuthorizedAppCode(
 int req_id,
 const AuthorizedAppCodeParameter* param,
 void* auth_code,
 int* issuer_id,
 bool* consent_required_error) {
 (void)issuer_id;
 if (req_id <= 0 || !param || !auth_code || !consent_required_error)
  return SCE_NP_AUTH_ERROR_INVALID_ARGUMENT;
 if (param->size != sizeof(AuthorizedAppCodeParameter))
  return SCE_NP_AUTH_ERROR_INVALID_SIZE;
 if (!param->authorizedAppClientId || !param->scope || (param->accessType != 0 && param->accessType != 1))
  return SCE_NP_AUTH_ERROR_INVALID_ARGUMENT;
 // A missing PSN connection is not a consent-required error. Callers
 // must not launch an authorization dialog on this failure.
 *consent_required_error = false;
 return SCE_NP_ERROR_SIGNED_OUT;
}

int APS5_VABI sceNpAuthGetIdTokenV3(int req_id, const void* param, void* id_token) {
 (void)req_id;
 (void)param;
 (void)id_token;
 NotImplemented_nid_no_patch(__func__);
 return 0;
}

int APS5_VABI sceNpAuthPollAsync(int req_id, int* result) {
 (void)req_id;
 if (result) *result = SCE_NP_ERROR_SIGNED_OUT;
 return NP_POLL_ASYNC_FINISHED;
}

int APS5_VABI sceNpAuthWaitAsync(int req_id, int* result) {
 (void)req_id;
 (void)result;
 NotImplemented_nid_no_patch(__func__);
 return 0;
}

}
