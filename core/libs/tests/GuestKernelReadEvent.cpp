#include "SceTypes.hpp"
#include "prx/libkernel/Equeue/Equeue.hpp"
#include "prx/libkernel/KernelErrors.hpp"

#include <cstdlib>

extern "C" {
int APS5_VABI sceKernelCreateEqueue(KernelEqueue* eq, const char* name);
int APS5_VABI sceKernelDeleteEqueue(KernelEqueue eq);
int APS5_VABI sceKernelAddUserEvent(KernelEqueue eq, int id);
int APS5_VABI sceKernelDeleteReadEvent(KernelEqueue eq, int fd);
int APS5_VABI sceKernelDeleteWriteEvent(KernelEqueue eq, int fd);
}

static void Require(bool value) {
    if (!value) std::abort();
}

int main() {
    constexpr int fd = 42;
    KernelEqueue queue = 0;
    Require(sceKernelCreateEqueue(&queue, "read-event-test") == EQUEUE_OK);

    // The registration is synthetic: this test validates event registration
    // removal, not host file/socket readiness polling.
    KernelEqueueEvent read{};
    read.event.ident = static_cast<uintptr_t>(fd);
    read.event.filter = EVFILT_READ;
    read.event.flags = EV_ADD;
    Require(EqueueAddEvent_nid_postfix(queue, read) == EQUEUE_OK);

    KernelEqueueEvent write{};
    write.event.ident = static_cast<uintptr_t>(fd);
    write.event.filter = EVFILT_WRITE;
    write.event.flags = EV_ADD;
    Require(EqueueAddEvent_nid_postfix(queue, write) == EQUEUE_OK);

    // All three filters can share one descriptor. Deleting WRITE must
    // preserve READ and USER; deleting READ must preserve USER.
    Require(sceKernelAddUserEvent(queue, fd) == EQUEUE_OK);
    Require(sceKernelDeleteWriteEvent(queue, fd) == EQUEUE_OK);
    Require(sceKernelDeleteWriteEvent(queue, fd) == SCE_KERNEL_ERROR_ENOENT);
    Require(sceKernelDeleteReadEvent(queue, fd) == EQUEUE_OK);
    Require(sceKernelDeleteReadEvent(queue, fd) == SCE_KERNEL_ERROR_ENOENT);
    Require(EqueueDeleteEvent_nid_postfix(queue, fd, EVFILT_USER) == EQUEUE_OK);

    // Exercise the reverse order: deleting READ must not delete WRITE.
    Require(EqueueAddEvent_nid_postfix(queue, read) == EQUEUE_OK);
    Require(EqueueAddEvent_nid_postfix(queue, write) == EQUEUE_OK);
    Require(sceKernelDeleteReadEvent(queue, fd) == EQUEUE_OK);
    Require(sceKernelDeleteWriteEvent(queue, fd) == EQUEUE_OK);

    Require(sceKernelDeleteEqueue(queue) == EQUEUE_OK);
    Require(sceKernelDeleteReadEvent(queue, fd) == SCE_KERNEL_ERROR_EBADF);
    Require(sceKernelDeleteWriteEvent(queue, fd) == SCE_KERNEL_ERROR_EBADF);
    Require(sceKernelDeleteReadEvent(0, fd) == SCE_KERNEL_ERROR_EBADF);
    Require(sceKernelDeleteWriteEvent(0, fd) == SCE_KERNEL_ERROR_EBADF);
    return 0;
}
