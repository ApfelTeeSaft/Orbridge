#include "SceTypes.hpp"
#include "prx/libkernel/Equeue/Equeue.hpp"
#include "prx/libkernel/KernelErrors.hpp"
#include "prx/libkernel/Socket/include/SocketPoll.hpp"

#include <cstdlib>
#include <cstddef>

extern "C" {
int APS5_VABI sceKernelCreateEqueue(KernelEqueue* eq, const char* name);
int APS5_VABI sceKernelDeleteEqueue(KernelEqueue eq);
int APS5_VABI sceKernelAddUserEvent(KernelEqueue eq, int id);
int APS5_VABI sceKernelAddReadEvent(KernelEqueue eq, int fd, std::size_t lowWater, void* userData);
int APS5_VABI sceKernelDeleteReadEvent(KernelEqueue eq, int fd);
int APS5_VABI sceKernelDeleteWriteEvent(KernelEqueue eq, int fd);
int APS5_VABI sceKernelWaitEqueue(KernelEqueue eq, KernelEvent* events, int num, int* count,
                                   const KernelUseconds* timeout);
}

static void Require(bool value) {
    if (!value) std::abort();
}

namespace {
constexpr int TestDescriptor = 42;
bool g_readReady = false;

// Model libSceNet's guest-descriptor table: unknown descriptors must never
// be treated as if they were host file handles or live sockets.
int FakeSocketPoller(KernelSocketPoll::Entry* entries, int count, int timeoutMs) {
    Require(count == 1 && timeoutMs == 0 && entries != nullptr);
    auto& entry = entries[0];
    entry.revents = entry.descriptor == TestDescriptor
        ? (g_readReady ? KernelSocketPoll::Readable : 0)
        : KernelSocketPoll::Unknown;
    return entry.revents == KernelSocketPoll::Readable ? 1 : 0;
}
}

int main() {
    KernelEqueue queue = 0;
    Require(sceKernelCreateEqueue(&queue, "read-event-test") == EQUEUE_OK);

    // No socket provider: do not register a watcher that will never fire.
    KernelSetSocketPoller_nid_no_patch(nullptr);
    Require(sceKernelAddReadEvent(queue, TestDescriptor, 1, nullptr) == SCE_KERNEL_ERROR_EOPNOTSUPP);
    KernelSetSocketPoller_nid_no_patch(FakeSocketPoller);

    Require(sceKernelAddReadEvent(0, TestDescriptor, 1, nullptr) == SCE_KERNEL_ERROR_EBADF);
    Require(sceKernelAddReadEvent(queue, -1, 1, nullptr) == SCE_KERNEL_ERROR_EBADF);
    Require(sceKernelAddReadEvent(queue, 999, 1, nullptr) == SCE_KERNEL_ERROR_EBADF);

    int userdata = 99;
    Require(sceKernelAddReadEvent(queue, TestDescriptor, 1, &userdata) == EQUEUE_OK);
    KernelEvent received{};
    int receivedCount = -1;
    constexpr KernelUseconds zeroTimeout = 0;
    Require(sceKernelWaitEqueue(queue, &received, 1, &receivedCount, &zeroTimeout)
            == SCE_KERNEL_ERROR_ETIMEDOUT);
    Require(receivedCount == 0);

    g_readReady = true;
    Require(sceKernelWaitEqueue(queue, &received, 1, &receivedCount, &zeroTimeout) == EQUEUE_OK);
    Require(receivedCount == 1);
    Require(received.ident == static_cast<uintptr_t>(TestDescriptor));
    Require(received.filter == EVFILT_READ);
    Require(received.udata == &userdata);

    // Level-readiness is rechecked after delivery and clears when drained.
    g_readReady = false;
    Require(sceKernelWaitEqueue(queue, &received, 1, &receivedCount, &zeroTimeout)
            == SCE_KERNEL_ERROR_ETIMEDOUT);
    Require(receivedCount == 0);

    KernelEqueueEvent write{};
    write.event.ident = static_cast<uintptr_t>(TestDescriptor);
    write.event.filter = EVFILT_WRITE;
    write.event.flags = EV_ADD;
    Require(EqueueAddEvent_nid_postfix(queue, write) == EQUEUE_OK);

    // All three filters share a descriptor. Deleting WRITE must leave READ
    // registered; deleting READ must preserve the user event.
    Require(sceKernelAddUserEvent(queue, TestDescriptor) == EQUEUE_OK);
    Require(sceKernelDeleteWriteEvent(queue, TestDescriptor) == EQUEUE_OK);
    Require(sceKernelDeleteWriteEvent(queue, TestDescriptor) == SCE_KERNEL_ERROR_ENOENT);
    g_readReady = true;
    Require(sceKernelWaitEqueue(queue, &received, 1, &receivedCount, &zeroTimeout) == EQUEUE_OK);
    Require(received.filter == EVFILT_READ);
    g_readReady = false;
    Require(sceKernelDeleteReadEvent(queue, TestDescriptor) == EQUEUE_OK);
    Require(sceKernelDeleteReadEvent(queue, TestDescriptor) == SCE_KERNEL_ERROR_ENOENT);
    Require(EqueueDeleteEvent_nid_postfix(queue, TestDescriptor, EVFILT_USER) == EQUEUE_OK);

    // Reverse order: deleting READ does not affect WRITE.
    Require(sceKernelAddReadEvent(queue, TestDescriptor, 1, &userdata) == EQUEUE_OK);
    Require(EqueueAddEvent_nid_postfix(queue, write) == EQUEUE_OK);
    Require(sceKernelDeleteReadEvent(queue, TestDescriptor) == EQUEUE_OK);
    Require(sceKernelDeleteWriteEvent(queue, TestDescriptor) == EQUEUE_OK);

    Require(sceKernelDeleteEqueue(queue) == EQUEUE_OK);
    Require(sceKernelDeleteReadEvent(queue, TestDescriptor) == SCE_KERNEL_ERROR_EBADF);
    Require(sceKernelDeleteWriteEvent(queue, TestDescriptor) == SCE_KERNEL_ERROR_EBADF);
    KernelSetSocketPoller_nid_no_patch(nullptr);
    return 0;
}
