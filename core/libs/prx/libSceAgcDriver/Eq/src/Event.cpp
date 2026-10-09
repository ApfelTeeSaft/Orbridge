#include "prx/libSceAgcDriver/Eq/include/Event.hpp"

#include <algorithm>
#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <cstdint>
#include <cstddef>
#include <mutex>
#include <stdexcept>
#include <string>
#include <vector>
#include "SceTypes.hpp"
#include "prx/libc/include/General.hpp"
#include "prx/libkernel/Equeue/Equeue.hpp"

namespace {

constexpr int16_t EvfiltGraphicsCore = -14;

struct Registration {
    KernelEqueue eq;
    int id;
};

std::mutex g_mutex;
std::vector<Registration> g_registrations;

// Trace only the graphics end-of-pipe events which back filter -14.
// Do not synthesize interrupts: this is purely diagnostic.
bool TraceAgcEop() {
    static const bool enabled = [] {
        const char* value = std::getenv("APS5_TRACE_AGC_EOP");
        return value && *value && !(value[0] == '0' && value[1] == '\0');
    }();
    return enabled;
}
std::atomic<std::uint64_t> g_deliveryCount{0};

}

void AgcDriverDeliverEopInterrupt(std::uint32_t queue) {
    std::vector<Registration> registrations;
    {
        std::lock_guard lock(g_mutex);
        registrations = g_registrations;
    }
    const auto serial = ++g_deliveryCount;
    std::size_t matches = 0;
    for (const auto& registration : registrations) {
        if (registration.id == static_cast<int>(queue)) {
            ++matches;
            const int result = EqueueTriggerEvent_nid_postfix(registration.eq, static_cast<uintptr_t>(registration.id), EvfiltGraphicsCore, nullptr);
            if (TraceAgcEop() && (serial <= 64 || serial % 128 == 0 || result != EQUEUE_OK))
                std::fprintf(stderr, "[agc.eop] deliver seq=%llu queue=%u eq=%llu result=0x%x\n",
                    static_cast<unsigned long long>(serial), queue,
                    static_cast<unsigned long long>(registration.eq), static_cast<unsigned>(result));
        }
    }
    if (TraceAgcEop() && (serial <= 64 || serial % 128 == 0 || matches == 0)) {
        std::fprintf(stderr, "[agc.eop] delivery-summary seq=%llu queue=%u registered=%zu matching=%zu\n",
            static_cast<unsigned long long>(serial), queue, registrations.size(), matches);
        std::fflush(stderr);
    }
}

extern "C" {

int APS5_VABI sceAgcDriverAddEqEvent(KernelEqueue eq, int id, void* udata) {
    if (eq == 0 || !EqueuePin_nid_postfix(eq)) {
        throw std::runtime_error(std::string(__func__) + ": invalid event queue");
    }
    KernelEqueueEvent event{};
    event.event.ident = static_cast<uintptr_t>(id);
    event.event.filter = EvfiltGraphicsCore;
    event.event.flags = EV_ADD | EV_CLEAR;
    event.event.udata = udata;
    event.filter.triggerFunc = [](KernelEqueueEvent* e, void*) {
        e->event.data = e->triggered ? e->event.data + 1 : 1;
        e->triggered = true;
    };
    event.filter.resetFunc = [](KernelEqueueEvent* e) {
        e->triggered = false;
        e->event.data = 0;
    };
    const int result = EqueueAddEvent_nid_postfix(eq, event);
    if (result != EQUEUE_OK) {
        throw std::runtime_error(std::string(__func__) + ": event queue rejected the event");
    }
    std::lock_guard lock(g_mutex);
    if (std::none_of(g_registrations.begin(), g_registrations.end(), [&](const Registration& r) { return r.eq == eq && r.id == id; })) {
        g_registrations.push_back({eq, id});
    }
    if (TraceAgcEop()) {
        std::fprintf(stderr, "[agc.eop] register eq=%llu queue=%d registered=%zu\n",
            static_cast<unsigned long long>(eq), id, g_registrations.size());
        std::fflush(stderr);
    }
    return 0;
}

int APS5_VABI sceAgcDriverDeleteEqEvent(KernelEqueue eq, int id) {
    {
        std::lock_guard lock(g_mutex);
        std::erase_if(g_registrations, [&](const Registration& r) { return r.eq == eq && r.id == id; });
    }
    if (EqueueDeleteEvent_nid_postfix(eq, static_cast<uintptr_t>(id), EvfiltGraphicsCore) != EQUEUE_OK) {
        throw std::runtime_error(std::string(__func__) + ": event is not registered");
    }
    return 0;
}

}
